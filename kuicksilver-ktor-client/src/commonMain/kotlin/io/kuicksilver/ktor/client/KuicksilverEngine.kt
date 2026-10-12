// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.HttpClientEngineBase
import io.ktor.client.engine.HttpClientEngineCapability
import io.ktor.client.engine.callContext
import io.ktor.client.plugins.HttpTimeoutCapability
import io.ktor.client.plugins.sse.SSECapability
import io.ktor.client.plugins.websocket.WEBSOCKETS_KEY
import io.ktor.client.plugins.websocket.WebSocketCapability
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.isSecure
import io.ktor.network.selector.SelectorManager
import io.ktor.util.date.getTimeMillis
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.ktor.client.h1.H1Pool
import io.kuicksilver.ktor.client.h3.H3NotSent
import io.kuicksilver.ktor.client.h3.H3Pool
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.isReplayable
import io.kuicksilver.ktor.client.h3.H3Target
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.CoroutineContext

/** `HttpClient(Kuicksilver)`: HTTP/3 and HTTP/1.1 over TLS 1.3 (docs/guide/ktor.md). */
@OptIn(InternalAPI::class, DelicateCoroutinesApi::class)
internal class KuicksilverEngine(
    override val config: KuicksilverEngineConfig,
) : HttpClientEngineBase("ktor-kuicksilver") {
    // WebSocketExtensionsCapability is not declared in v1: no extension negotiation; no Unix sockets
    override val supportedCapabilities: Set<HttpClientEngineCapability<*>> =
        setOf(HttpTimeoutCapability, WebSocketCapability, SSECapability)

    /**
     * The requests' job, a supervisor child of the base context (as in the CIO engine): `close()` completes it, and once its
     * calls are done the cleanup below closes the pools, the UDP endpoint and the selector. Without it the cleanup waited
     * for its own parent and every closed client kept its sockets (found by the vendored Ktor client contract tests).
     */
    override val coroutineContext: CoroutineContext = super.coroutineContext.let { it + SupervisorJob(it[Job]) }
    private val selector = SelectorManager(dispatcher)
    private val engineJob = SupervisorJob(coroutineContext[Job])

    /** Background work that outlives a call (a QUIC setup that lost the race); completed by [close] so the cleanup can run. */
    private val engineScope = CoroutineScope(coroutineContext + engineJob)
    private val h1 = H1Pool(config, selector)
    private val h3 = H3Pool(config)
    private val altSvc = AltSvcCache(config.http3.altSvcStore) { getTimeMillis() }
    private val altSvcLock = Mutex()

    /** Serializes [FileAltSvcStore] writes, which run after [altSvcLock] is released; internal for tests. */
    internal val altSvcWriteLock = Mutex()

    /** Broken alternatives and networks where QUIC worked; internal for tests. */
    internal val brokenAltSvc = BrokenAltSvc { getTimeMillis() }
    private val race = ProtocolRace(config.http3.softDelay, config.http3.hardDelay)
    private val srtt = HashMap<String, kotlin.time.Duration>() // per origin, from the last HTTP/3 connection
    private var lastNetwork: String? = null
    private var networkSeen = false

    init {
        val requests = coroutineContext[Job]!!
        GlobalScope.launch(super.coroutineContext, start = CoroutineStart.ATOMIC) {
            try {
                requests.join()
            } finally {
                withContext(NonCancellable) { altSvcUpdate {} } // a snapshot no request took (an expiry dropped on lookup)
                h1.closeAll()
                h3.close()
                selector.close()
            }
        }
    }

    override fun close() {
        engineJob.complete()
        super.close()
    }

    override suspend fun execute(data: HttpRequestData): HttpResponseData {
        val callContext = callContext()
        val url = data.url
        // HTTP/3 needs TLS and no proxy (through a proxy only HTTP/1.1)
        if (!url.protocol.isSecure() || config.proxy != null ||
            config.http3.discovery == Http3DiscoveryMode.H1Only
        ) {
            return h1.execute(data, callContext)
        }
        val target = H3Target(url.host, url.host, url.port)
        val webSocket = data.attributes.contains(WEBSOCKETS_KEY)
        val network = checkNetwork()
        return when {
            config.http3.discovery == Http3DiscoveryMode.H3Only -> {
                try {
                    h3.execute(target, data, callContext)
                } catch (e: H3NotSent) {
                    throw e.cause
                        ?: e
                }
            }

            config.http3.discovery == Http3DiscoveryMode.Preferred || HostPort(url.host, url.port) in config.http3.quicHints -> {
                // WebSockets take HTTP/3 only on a connection that already allows Extended CONNECT (RFC 9220; else h1.1 Upgrade first)
                if (webSocket &&
                    !h3.canConnectProtocol(target)
                ) {
                    h1.execute(data, callContext)
                } else {
                    raced(target, data, callContext, network, emptyList())
                }
            }

            else -> {
                auto(data, callContext, target, webSocket, network)
            }
        }
    }

    /** A new network (`networkId`) forgets broken marks, QUIC confirmation and, if asked, non-persistent alternatives. */
    private suspend fun checkNetwork(): String? =
        altSvcUpdate {
            val id = config.http3.networkId()
            if (networkSeen &&
                id != lastNetwork
            ) {
                brokenAltSvc.onNetworkChanged()
                altSvc.onNetworkChanged(config.http3.clearOnNetworkChange)
            }
            networkSeen = true
            lastNetwork = id
            id
        }

    /**
     * Runs [block] under [altSvcLock], then writes the store's new content, if any, outside it (threat-model 3.18). A
     * snapshot taken under the lock is written even when the caller is cancelled meanwhile: nobody else would write it.
     */
    private suspend fun <T> altSvcUpdate(block: () -> T): T {
        val (value, write) = altSvcLock.withLock { block() to altSvc.takePendingWrite() }
        if (write != null) withContext(NonCancellable) { altSvcWriteLock.withLock { write() } }
        return value
    }

    /**
     * HTTP/3 against HTTP/1.1 (docs/guide/ktor.md): connection setups race ([ProtocolRace]); the request runs once, on the winner.
     * A broken alternative goes straight to HTTP/1.1; HTTP/3 failing while HTTP/1.1 works marks it broken. An HTTP/1.1
     * connection that lost the race is closed; when both setups fail, the HTTP/1.1 failure is the result (the race already
     * was the one HTTP/1.1 attempt, RFC 8305 section 5).
     */
    private suspend fun raced(
        t: H3Target,
        data: HttpRequestData,
        callContext: CoroutineContext,
        network: String?,
        extraHeaders: List<Pair<String, String>>,
    ): HttpResponseData {
        val origin = originKey(data.url)
        val alt = "${t.host}:${t.port}"
        val (broken, confirmed, rtt) =
            altSvcLock.withLock {
                Triple(brokenAltSvc.isBroken(origin, alt), brokenAltSvc.quicConfirmedOn(network), srtt[origin])
            }
        if (broken) return h1.execute(data, callContext)
        // an established HTTP/3 connection is used as is: the race is about setting one up
        if (h3.existing(t) != null) return h3WithFallback(t, data, callContext, extraHeaders)
        // the HTTP/3 attempt outlives a lost race: it fills the pool for the next request, or marks the alternative broken
        val h3Attempt = engineScope.async { h3.connection(t, data) }
        val result =
            race.race<Any>({ h3Attempt.await() }, { h1.open(data) }, rtt, confirmed, onLoser = {
                (it as? io.kuicksilver.ktor.client.h1.H1Connection)?.close()
            })
        return when (result.winner) {
            Protocol.H3 -> {
                val conn = result.value as io.kuicksilver.http3.Http3Connection
                altSvcLock.withLock {
                    brokenAltSvc.confirmQuic(network)
                    brokenAltSvc.markWorking(origin, alt)
                    srtt[origin] =
                        conn.quic.stats.smoothedRtt
                }
                h3WithFallback(t, data, callContext, extraHeaders)
            }

            Protocol.H1 -> {
                h3Attempt.invokeOnCompletion { cause ->
                    engineScope.launch {
                        altSvcLock.withLock {
                            if (cause ==
                                null
                            ) {
                                brokenAltSvc.confirmQuic(network)
                                runCatching {
                                    srtt[origin] =
                                        h3Attempt
                                            .getCompleted()
                                            .quic.stats.smoothedRtt
                                }
                            } // lost the race, but QUIC works here
                            else if (cause !is CancellationException) {
                                brokenAltSvc.markBroken(origin, alt)
                            }
                        }
                    }
                }
                h1.execute(data, callContext, result.value as io.kuicksilver.ktor.client.h1.H1Connection)
            }
        }
    }

    /** The cached alternatives for the origin of [url] (tests). */
    internal suspend fun altSvcSnapshot(url: io.ktor.http.Url): List<AltSvcEntry> =
        altSvcLock.withLock { config.http3.altSvcStore.get(originKey(url)) }

    /** Whether an HTTP/3 connection to the origin of [url] is open (tests). */
    internal suspend fun hasH3Connection(url: io.ktor.http.Url): Boolean = h3.existing(H3Target(url.host, url.host, url.port)) != null

    private fun originKey(url: io.ktor.http.Url): String = "${url.protocol.name}://${url.host}:${url.port}"

    /**
     * `Auto` (RFC 7838): HTTP/3 to a live alternative the origin announced, with `Alt-Used`; otherwise HTTP/1.1,
     * learning `Alt-Svc` from its responses (always over verified TLS here: the engine's TLS rejects what the trust
     * configuration rejects). A 421 from the alternative drops it and the request goes to the origin over HTTP/1.1.
     */
    private suspend fun auto(
        data: HttpRequestData,
        callContext: CoroutineContext,
        origin: H3Target,
        webSocket: Boolean,
        network: String?,
    ): HttpResponseData {
        val url = data.url
        val alt = altSvcUpdate { altSvc.h3For(url) }
        if (alt != null) {
            val altHost = alt.host ?: url.host
            val t = H3Target(url.host, altHost, alt.port)
            if (!webSocket || h3.canConnectProtocol(t)) {
                val r = raced(t, data, callContext, network, listOf("alt-used" to "$altHost:${alt.port}"))
                // an HTTP/1.1 answer (broken alternative, lost race, fallback) still carries the origin's Alt-Svc: a new list or `clear` replaces the cached one (RFC 7838 section 3)
                if (r.version !=
                    HttpProtocolVersion.HTTP_3_0
                ) {
                    altSvcUpdate {
                        altSvc.onResponse(
                            url,
                            r.statusCode.value,
                            r.headers.getAll("Alt-Svc").orEmpty(),
                            verifiedTls = url.protocol.isSecure(),
                        )
                    }
                }
                if (r.statusCode.value != 421 || r.version != HttpProtocolVersion.HTTP_3_0) return r
                altSvcUpdate { altSvc.remove(url) }
                if (!data.body.isReplayable()) {
                    throw H3BodyConsumed(
                        "421 Misdirected Request from the alternative, and the request body was already consumed",
                    )
                }
            }
        }
        val r = h1.execute(data, callContext)
        altSvcUpdate {
            altSvc.onResponse(url, r.statusCode.value, r.headers.getAll("Alt-Svc").orEmpty(), verifiedTls = url.protocol.isSecure())
        }
        return r
    }

    /**
     * HTTP/3, falling back to HTTP/1.1 when it fails before the response headers: always if the request cannot have been
     * sent, otherwise for idempotent methods only (as Chromium's `retry_without_alt_svc_on_quic_errors`). A fallback that
     * succeeds after a connection-level HTTP/3 failure marks the alternative broken (RFC 7838 section 2.4, [marksAlternativeBroken]).
     */
    private suspend fun h3WithFallback(
        target: H3Target,
        data: HttpRequestData,
        callContext: CoroutineContext,
        extraHeaders: List<Pair<String, String>> = emptyList(),
    ): HttpResponseData =
        try {
            h3.execute(target, data, callContext, extraHeaders)
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (
            e: H3NotSent,
        ) {
            fallbackToH1(target, data, callContext, e)
        } catch (
            e: Throwable,
        ) {
            if (data.method.isIdempotent() && (e is QuicException || e is Http3Exception) &&
                data.body.isReplayable()
            ) {
                fallbackToH1(target, data, callContext, e)
            } else {
                throw e
            }
        } // a streamed body HTTP/3 consumed is never replayed

    private suspend fun fallbackToH1(
        target: H3Target,
        data: HttpRequestData,
        callContext: CoroutineContext,
        h3Failure: Throwable,
    ): HttpResponseData {
        val r = h1.execute(data, callContext)
        if (marksAlternativeBroken(h3Failure)) {
            altSvcLock.withLock { brokenAltSvc.markBroken(originKey(data.url), "${target.host}:${target.port}") }
        }
        return r
    }

    override fun toString(): String = "Kuicksilver"
}

/**
 * Whether an HTTP/3 failure says the alternative itself does not work (RFC 7838 section 2.4): the connection could not be
 * set up (handshake, transport) or failed as a whole. A single stream's reset, a malformed message, a refused request
 * and a field section refused locally are about one exchange and leave the alternative usable.
 */
internal fun marksAlternativeBroken(e: Throwable): Boolean =
    when (e) {
        is H3NotSent -> e.cause !is Http3Exception.RequestNotProcessed
        is QuicException.StreamError -> false
        is QuicException -> true
        is Http3Exception.Protocol -> e.streamId == null
        is Http3Exception.Qpack, is Http3Exception.Settings -> true
        else -> false
    }

/** RFC 9110 section 9.2.2. */
internal fun HttpMethod.isIdempotent(): Boolean =
    this in setOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options, HttpMethod.Put, HttpMethod.Delete, HttpMethod("TRACE"))
