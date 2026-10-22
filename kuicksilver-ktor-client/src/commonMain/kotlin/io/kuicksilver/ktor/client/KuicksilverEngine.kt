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
import io.ktor.client.plugins.websocket.WebSocketExtensionsCapability
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.isSecure
import io.ktor.util.date.getTimeMillis
import io.ktor.utils.io.InternalAPI
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.ktor.client.h1.H1Pool
import io.kuicksilver.ktor.client.h3.H3NotSent
import io.kuicksilver.ktor.client.h3.H3Pool
import io.kuicksilver.ktor.client.h3.H3Pool.Companion.isReplayable
import io.kuicksilver.ktor.client.h3.H3Target
import io.kuicksilver.ktor.network.engineSelector
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.CoroutineContext

/** `HttpClient(Kuicksilver)`: HTTP/3 and HTTP/1.1 over TLS 1.3 (docs/guide/ktor.md). */
@OptIn(InternalAPI::class, DelicateCoroutinesApi::class)
internal class KuicksilverEngine(
    override val config: KuicksilverEngineConfig,
) : HttpClientEngineBase("ktor-kuicksilver") {
    // WebSocket extensions are negotiated by Ktor's plugin; the engine checks the answer against the offer and the frames'
    // RSV bits against what was negotiated (RFC 6455 sections 4.1 and 5.2). No Unix sockets
    override val supportedCapabilities: Set<HttpClientEngineCapability<*>> =
        setOf(HttpTimeoutCapability, WebSocketCapability, WebSocketExtensionsCapability, SSECapability)

    /**
     * The requests' job, a supervisor child of the base context (as in the CIO engine): `close()` completes it, and once its
     * calls are done the cleanup below closes the pools, the UDP endpoint and the selector. Without it the cleanup waited
     * for its own parent and every closed client kept its sockets (found by the vendored Ktor client contract tests).
     */
    override val coroutineContext: CoroutineContext = super.coroutineContext.let { it + SupervisorJob(it[Job]) }

    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private val selector = engineSelector(dispatcher) // a socket closed on it is released at once (EngineSelector.kt)
    private val engineJob = SupervisorJob(coroutineContext[Job])

    /** Background work that outlives a call (a QUIC setup that lost the race); completed by [close] so the cleanup can run. */
    private val engineScope = CoroutineScope(coroutineContext + engineJob)

    /** The [KuicksilverEventListener] of the configuration, behind a guard that never fails a call. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val events = EngineEvents(config.eventListener, config.logger ?: config.http3.endpoint.logger)
    internal val h1 = H1Pool(config, selector, events) // internal for tests (the engine's session cache)
    internal val h3 = H3Pool(config, events) // internal for tests (0-RTT reconnects)
    private val altSvc = AltSvcCache(config.http3.altSvcStore) { getTimeMillis() }
    private val altSvcLock = Mutex()

    /** Serializes [FileAltSvcStore] writes, which run after [altSvcLock] is released; internal for tests. */
    internal val altSvcWriteLock = Mutex()

    /** Broken alternatives and networks where QUIC worked; internal for tests. */
    internal val brokenAltSvc = BrokenAltSvc { getTimeMillis() }
    private val race = ProtocolRace(config.http3.hardDelay)
    private val srtt = LinkedHashMap<String, kotlin.time.Duration>() // per origin, from the last HTTP/3 connection; LRU-bounded
    private var lastNetwork: String? = null
    private var networkSeen = false

    /** The cleanup that runs once every request finished after [close]; internal so a test can wait for it. */
    internal val cleanup: Job

    /** Closes expired idle connections of both pools and prunes their bookkeeping; cancelled by [close]. */
    private val reaper: Job = engineScope.launch(CoroutineName("kuicksilver-pool-reaper")) { reapIdleConnections(h1, h3, config) }

    init {
        val requests = coroutineContext[Job]!!
        cleanup =
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
        reaper.cancel()
        engineJob.complete()
        super.close()
    }

    override suspend fun execute(data: HttpRequestData): HttpResponseData {
        events.emit("callStart") { callStart(data) }
        val callContext = callContext()
        val r =
            try {
                AbandonableBody.guard(route(data, callContext), callContext)
            } catch (e: Throwable) {
                events.emit("callFailed") { callFailed(data, e) }
                throw e
            }
        events.emit("callEnd") { callEnd(data, r.version, r.statusCode.value) }
        return r
    }

    private fun selected(
        data: HttpRequestData,
        protocol: HttpProtocolVersion,
        reason: ProtocolReason,
    ) = events.emit("protocolSelected") { protocolSelected(data, protocol, reason) }

    private suspend fun route(
        data: HttpRequestData,
        callContext: CoroutineContext,
    ): HttpResponseData {
        val url = data.url
        // H3Only promises HTTP/3 or a failure, never TCP: through a proxy there is no HTTP/3 (UDP would need CONNECT-UDP,
        // RFC 9298, or SOCKS5 UDP ASSOCIATE, neither supported), so the request fails instead of going over HTTP/1.1
        // HTTP/3 is only for https (RFC 9114 section 3.1): an http:// or ws:// request fails too, never goes over TCP
        if (!url.protocol.isSecure() && config.http3.discovery == Http3DiscoveryMode.H3Only) {
            throw UnsupportedOperationException(
                "Http3DiscoveryMode.H3Only: HTTP/3 needs an https URL (RFC 9114 section 3.1), not ${url.protocol.name}; " +
                    "use https or another discovery mode",
            )
        }
        if (config.proxy != null && url.protocol.isSecure() && config.http3.discovery == Http3DiscoveryMode.H3Only) {
            throw UnsupportedOperationException(
                "Http3DiscoveryMode.H3Only: HTTP/3 cannot go through the configured proxy (UDP through an HTTP CONNECT or " +
                    "SOCKS5 proxy is not supported); remove the proxy or use another discovery mode",
            )
        }
        // HTTP/3 needs TLS and no proxy (through a proxy only HTTP/1.1)
        if (!url.protocol.isSecure() || config.proxy != null ||
            config.http3.discovery == Http3DiscoveryMode.H1Only
        ) {
            selected(
                data,
                HttpProtocolVersion.HTTP_1_1,
                if (config.http3.discovery == Http3DiscoveryMode.H1Only && url.protocol.isSecure() && config.proxy == null) {
                    ProtocolReason.Configuration
                } else {
                    ProtocolReason.NotSecure
                },
            )
            return h1.execute(data, callContext)
        }
        val target = H3Target(url.host, url.host, url.port)
        val webSocket = data.attributes.contains(WEBSOCKETS_KEY)
        val network = checkNetwork()
        return when {
            config.http3.discovery == Http3DiscoveryMode.H3Only -> {
                selected(data, HttpProtocolVersion.HTTP_3_0, ProtocolReason.Configuration)
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
                    selected(data, HttpProtocolVersion.HTTP_1_1, ProtocolReason.WebSocket)
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
        // one resolution for both sides of the race and a fallback after it (RFC 8305 section 3)
        val dns = config.newRequestDns()
        val (broken, confirmed, rtt) =
            altSvcLock.withLock {
                Triple(brokenAltSvc.isBroken(origin, alt), brokenAltSvc.quicConfirmedOn(network), srtt[origin])
            }
        if (broken) {
            selected(data, HttpProtocolVersion.HTTP_1_1, ProtocolReason.BrokenAlternative)
            return h1.execute(data, callContext, dns = dns)
        }
        // an established HTTP/3 connection is used as is: the race is about setting one up
        if (h3.existing(t) != null) {
            selected(data, HttpProtocolVersion.HTTP_3_0, ProtocolReason.ExistingConnection)
            return h3WithFallback(t, data, callContext, extraHeaders, dns)
        }
        // the HTTP/3 attempt outlives a lost race: it fills the pool for the next request, or marks the alternative broken.
        // A 0-RTT connection is usable before its handshake, but on a network where QUIC was never seen working it must
        // complete the handshake to win (as Chromium requires confirmation there): a path that drops UDP then loses to
        // HTTP/1.1 at once instead of holding the request until the connect timeout
        val h3Attempt =
            engineScope.async {
                h3.connection(t, data, dns).also { if (!confirmed) it.quic.awaitHandshake() }
            }
        val result =
            race.race<Any>({ h3Attempt.await() }, { h1.open(data, dns) }, rtt, confirmed, onLoser = {
                (it as? H1Pool.Opened)?.let { o -> h1.recycle(o.connection) } // unused: back to the pool
            })
        val winner = if (result.winner == Protocol.H3) HttpProtocolVersion.HTTP_3_0 else HttpProtocolVersion.HTTP_1_1
        events.emit("raceEnded") { raceEnded(data, winner, race.headStart(rtt, confirmed), result.h3Failure) }
        selected(data, winner, ProtocolReason.Race)
        return when (result.winner) {
            Protocol.H3 -> {
                val conn = result.value as io.kuicksilver.http3.Http3Connection
                // QUIC works here and the alternative works only once the handshake completed, not on a 0-RTT start
                // (Chromium marks QUIC working at handshake confirmation); the RTT is a measured one then. A failed
                // handshake marks nothing here: the request's fallback marks the alternative broken
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                if (conn.quic.isHandshakeComplete) {
                    altSvcLock.withLock { recordQuicWorking(network, origin, alt, conn) }
                } else {
                    engineScope.launch {
                        if (runCatching { conn.quic.awaitHandshake() }.isSuccess) {
                            altSvcLock.withLock { recordQuicWorking(network, origin, alt, conn) }
                        }
                    }
                }
                h3WithFallback(t, data, callContext, extraHeaders, dns)
            }

            Protocol.H1 -> {
                h3Attempt.invokeOnCompletion { cause ->
                    engineScope.launch {
                        // a 0-RTT connection counts once its handshake completed (or failed)
                        val outcome =
                            cause ?: runCatching { h3Attempt.getCompleted().quic.awaitHandshake() }.exceptionOrNull()
                        altSvcLock.withLock {
                            if (outcome == null) {
                                // lost the race, but QUIC works here
                                brokenAltSvc.confirmQuic(network)
                                rememberSrtt(
                                    origin,
                                    h3Attempt
                                        .getCompleted()
                                        .quic.stats.smoothedRtt,
                                )
                            } else if (outcome !is CancellationException) {
                                brokenAltSvc.markBroken(origin, alt)
                                events.emit("altSvcMarkedBroken") { altSvcMarkedBroken(origin, alt) }
                            }
                        }
                    }
                }
                h1.execute(data, callContext, result.value as H1Pool.Opened, dns)
            }
        }
    }

    /** Under [altSvcLock]: QUIC completed a handshake on [network] through [alt] of [origin], with [conn]'s measured RTT. */
    private fun recordQuicWorking(
        network: String?,
        origin: String,
        alt: String,
        conn: io.kuicksilver.http3.Http3Connection,
    ) {
        brokenAltSvc.confirmQuic(network)
        brokenAltSvc.markWorking(origin, alt)
        rememberSrtt(origin, conn.quic.stats.smoothedRtt)
    }

    /** The cached alternatives for the origin of [url] (tests). */
    internal suspend fun altSvcSnapshot(url: io.ktor.http.Url): List<AltSvcEntry> =
        altSvcLock.withLock { config.http3.altSvcStore.get(originKey(url)) }

    /** Under [altSvcLock]: the smoothed RTT of [origin]'s last HTTP/3 connection; internal for tests. */
    internal fun rememberSrtt(
        origin: String,
        rtt: kotlin.time.Duration,
    ) {
        srtt.remove(origin)
        srtt[origin] = rtt
        srtt.evictEldest(AltSvcCache.MAX_ORIGINS)
    }

    /** The engine's table sizes (the resource probe, [KuicksilverClientProbe]). */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal suspend fun probeSizes(): Map<String, Long> {
        val h1Pool = h1.pool
        val (broken, rtts) = altSvcLock.withLock { brokenAltSvc.size to srtt.size }
        return linkedMapOf(
            "client.h1Live" to h1Pool.liveCount.toLong(),
            "client.h1Idle" to h1Pool.idleCount.toLong(),
            "client.h1Routes" to h1Pool.routeCount.toLong(),
            "client.h1Waiters" to h1Pool.waiterCount.toLong(),
            "client.h1Sessions" to h1.sessions.size().toLong(),
            "client.h3Connections" to h3.connectionsForProbe().toLong(),
            "client.brokenAltSvc" to broken.toLong(),
            "client.srtt" to rtts.toLong(),
        )
    }

    /** The origins with a remembered RTT (tests). */
    internal val srttOrigins: Int get() = srtt.size

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
                events.emit("altSvcUsed") { altSvcUsed(data, "${uriHost(altHost)}:${alt.port}") }
                val r = raced(t, data, callContext, network, listOf("alt-used" to "${uriHost(altHost)}:${alt.port}"))
                // the origin's Alt-Svc on any answer, over HTTP/3 as over HTTP/1.1 (broken alternative, lost race, fallback): a
                // new list or `clear` replaces the cached one (RFC 7838 section 3); a 421 removes it
                altSvcUpdate {
                    altSvc.onResponse(
                        url,
                        r.statusCode.value,
                        r.headers.getAll("Alt-Svc").orEmpty(),
                        verifiedTls = url.protocol.isSecure(),
                    )
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
        selected(
            data,
            HttpProtocolVersion.HTTP_1_1,
            if (alt != null &&
                webSocket
            ) {
                ProtocolReason.WebSocket
            } else {
                ProtocolReason.NoAlternative
            },
        )
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
        dns: RequestDns = config.newRequestDns(),
    ): HttpResponseData =
        try {
            h3.execute(target, data, callContext, extraHeaders, dns)
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (
            e: H3NotSent,
        ) {
            fallbackToH1(target, data, callContext, e, dns)
        } catch (
            e: Throwable,
        ) {
            if (data.method.isIdempotent() && (e is QuicException || e is Http3Exception) &&
                data.body.isReplayable()
            ) {
                fallbackToH1(target, data, callContext, e, dns)
            } else {
                throw e
            }
        } // a streamed body HTTP/3 consumed is never replayed

    private suspend fun fallbackToH1(
        target: H3Target,
        data: HttpRequestData,
        callContext: CoroutineContext,
        h3Failure: Throwable,
        dns: RequestDns,
    ): HttpResponseData {
        val cause = if (h3Failure is H3NotSent) h3Failure.cause ?: h3Failure else h3Failure
        events.emit("fallback") { fallback(data, cause) }
        selected(data, HttpProtocolVersion.HTTP_1_1, ProtocolReason.Fallback)
        val r = h1.execute(data, callContext, dns = dns)
        if (marksAlternativeBroken(h3Failure)) {
            val origin = originKey(data.url)
            val alt = "${target.host}:${target.port}"
            altSvcLock.withLock { brokenAltSvc.markBroken(origin, alt) }
            events.emit("altSvcMarkedBroken") { altSvcMarkedBroken(origin, alt) }
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
