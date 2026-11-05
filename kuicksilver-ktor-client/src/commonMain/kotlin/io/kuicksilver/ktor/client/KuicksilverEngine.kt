// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ClientEngineClosedException
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
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
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
import kotlin.time.Duration.Companion.minutes

/** `HttpClient(Kuicksilver)`: HTTP/3, HTTP/2 and HTTP/1.1 over TLS 1.3 (docs/guide/ktor.md). */
@OptIn(InternalAPI::class, DelicateCoroutinesApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
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

    /** `proxyResolver`'s answers per route ([proxyFor]). */
    internal val proxies = ProxyRouting(config, events.logger)
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

    /** Set by [close]: new calls fail at once, the ones already made finish before the cleanup runs. */
    @kotlin.concurrent.Volatile
    private var closed = false

    override fun close() {
        closed = true
        h3.refuseDedicated() // at once, so a WebTransport call after close() fails instead of binding an endpoint
        reaper.cancel()
        engineJob.complete()
        super.close()
    }

    override suspend fun execute(data: HttpRequestData): HttpResponseData {
        // the requests' job stays active while calls finish after close(), so Ktor's own closed check lets new calls in
        if (closed) throw ClientEngineClosedException()
        events.emit("callStart") { callStart(data) }
        val callContext = callContext()
        // Ktor's call job is not a child of the requests' job: a child of that job lives as long as the call (its response
        // body included), so the cleanup after close() waits for the call (as CIO's) instead of closing its socket under it
        val inFlight = Job(this.coroutineContext[Job])
        callContext[Job]!!.invokeOnCompletion { inFlight.complete() }
        // a new one per call, also when the request's attributes came with one (a redirect or a retry copies them): the
        // pools count their retries in it, and the response hands it out
        val diagnostics = ProtocolDiagnostics()
        data.attributes.put(KuicksilverDiagnosticsKey, diagnostics)
        val r =
            try {
                AbandonableBody.guard(route(data, callContext, diagnostics), callContext)
            } catch (e: Throwable) {
                data.attributes.remove(KuicksilverDiagnosticsKey) // no response, no diagnostics: the exception says it
                events.emit("callFailed") { callFailed(data, e) }
                throw e
            }
        diagnostics.protocol = r.version
        if (r.version == HttpProtocolVersion.HTTP_3_0) diagnostics.fallback = null
        events.emit("callEnd") { callEnd(data, r.version, r.statusCode.value) }
        logDiagnostics(data, diagnostics)
        return r
    }

    /**
     * One line per answered call: at `diagnosticsLogLevel` when HTTP/3 was an option, or the mode would have used it, and
     * the call went over another protocol; at Debug otherwise (HTTP/3 served it, or it was never a candidate). Built only
     * when the logger wants that level.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun logDiagnostics(
        data: HttpRequestData,
        d: ProtocolDiagnostics,
    ) {
        val wanted = config.http3.diagnosticsLogLevel ?: return
        val level =
            when (d.fallback) {
                null, FallbackReason.NotSecure, FallbackReason.Configuration, FallbackReason.NoAlternative -> LogLevel.Debug
                else -> wanted
            }
        val logger = events.logger
        try {
            if (logger.isEnabled(level)) logger.log(level, d.line(data.method.value, data.url))
        } catch (_: Throwable) {
            // a logger that fails never fails the call (as EngineEvents.emit)
        }
    }

    /** Tells the listener and [d] that [data] goes over [protocol] for [reason]; reasons that say it all set [d]'s fallback. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun selected(
        data: HttpRequestData,
        protocol: HttpProtocolVersion,
        reason: ProtocolReason,
        d: ProtocolDiagnostics,
    ) {
        d.reason = reason
        d.fallback =
            if (protocol == HttpProtocolVersion.HTTP_3_0) {
                null
            } else {
                when (reason) {
                    ProtocolReason.NotSecure -> FallbackReason.NotSecure

                    ProtocolReason.Proxy -> FallbackReason.Proxy

                    ProtocolReason.Configuration -> FallbackReason.Configuration

                    ProtocolReason.NoAlternative -> FallbackReason.NoAlternative

                    ProtocolReason.BrokenAlternative -> FallbackReason.BrokenAlternative

                    ProtocolReason.WebSocket -> FallbackReason.WebSocket

                    ProtocolReason.Http3Disabled -> FallbackReason.Http3Disabled

                    // set by the caller from the HTTP/3 failure, if any
                    ProtocolReason.Race, ProtocolReason.Fallback, ProtocolReason.ExistingConnection -> d.fallback
                }
            }
        if (protocol == HttpProtocolVersion.HTTP_1_1 && d.h2Refused && d.fallback != FallbackReason.H2Refused) {
            // HTTP/1.1 because the server refused HTTP/2: that is what the call needs to say; the HTTP/3 reason stays in the log
            d.h3Fallback = d.fallback
            d.fallback = FallbackReason.H2Refused
        }
        events.emit("protocolSelected") { protocolSelected(data, protocol, reason) }
    }

    /**
     * The TCP path (HTTP/1.1, or HTTP/2 when the server picks it): `protocolSelected` goes out with the protocol of the
     * connection once it is in hand ([H1Pool.execute]), for [reason]; [after] runs after it.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun tcp(
        data: HttpRequestData,
        callContext: CoroutineContext,
        reason: ProtocolReason,
        d: ProtocolDiagnostics,
        preopened: H1Pool.Opened? = null,
        dns: RequestDns = config.newRequestDns(),
        proxy: ResolvedProxy? = null,
        after: () -> Unit = {},
    ): HttpResponseData =
        h1.execute(data, callContext, preopened, dns, proxy) { protocol ->
            selected(data, protocol, reason, d)
            after()
        }

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun route(
        data: HttpRequestData,
        callContext: CoroutineContext,
        d: ProtocolDiagnostics,
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
        // the kill switch, read once per request before anything connects; H3Only cannot fall back, so it fails
        val disabled =
            url.protocol.isSecure() && config.http3.discovery != Http3DiscoveryMode.H1Only && !http3Allowed()
        if (disabled && config.http3.discovery == Http3DiscoveryMode.H3Only) {
            throw UnsupportedOperationException("HTTP/3 is disabled by http3Allowed; Http3DiscoveryMode.H3Only never uses TCP")
        }
        val proxy = proxyFor(url) // explicit, else the resolver's: a proxy the engine cannot use fails here, never bypassed
        if (proxy != null && url.protocol.isSecure() && config.http3.discovery == Http3DiscoveryMode.H3Only) {
            throw UnsupportedOperationException(
                "Http3DiscoveryMode.H3Only: HTTP/3 cannot go through the proxy for ${url.host} (UDP through an HTTP CONNECT or " +
                    "SOCKS5 proxy is not supported); remove the proxy or use another discovery mode",
            )
        }
        // HTTP/3 needs TLS and no proxy (through a proxy only HTTP/1.1)
        if (!url.protocol.isSecure() || proxy != null ||
            config.http3.discovery == Http3DiscoveryMode.H1Only || disabled
        ) {
            val reason =
                when {
                    proxy != null -> ProtocolReason.Proxy
                    config.http3.discovery == Http3DiscoveryMode.H1Only && url.protocol.isSecure() -> ProtocolReason.Configuration
                    disabled -> ProtocolReason.Http3Disabled
                    else -> ProtocolReason.NotSecure
                }
            // the kill switch turns HTTP/3 off, not HTTP/2: the TCP path still offers h2
            val r = tcp(data, callContext, reason, d, proxy = proxy) // no Alt-Svc is used or learned through a proxy
            // switched off, Auto keeps learning Alt-Svc, so switching back needs no warm-up
            if (disabled && proxy == null && config.http3.discovery == Http3DiscoveryMode.Auto) {
                altSvcUpdate {
                    altSvc.onResponse(url, r.statusCode.value, r.headers.getAll("Alt-Svc").orEmpty(), verifiedTls = true)
                }
            }
            return r
        }
        val target = H3Target(url.host, url.host, url.port)
        val webSocket = data.attributes.contains(WEBSOCKETS_KEY)
        val network = checkNetwork()
        return when {
            config.http3.discovery == Http3DiscoveryMode.H3Only -> {
                d.alternative(target.host, target.port, AlternativeSource.H3Only)
                selected(data, HttpProtocolVersion.HTTP_3_0, ProtocolReason.Configuration, d)
                try {
                    h3.execute(target, data, callContext)
                } catch (e: H3NotSent) {
                    throw e.cause
                        ?: e
                }
            }

            config.http3.discovery == Http3DiscoveryMode.Preferred || HostPort(url.host, url.port) in config.http3.quicHints -> {
                d.alternative(
                    target.host,
                    target.port,
                    if (config.http3.discovery == Http3DiscoveryMode.Preferred) AlternativeSource.Preferred else AlternativeSource.QuicHint,
                )
                // WebSockets take HTTP/3 only on a connection that already allows Extended CONNECT (RFC 9220; else h1.1 Upgrade first)
                if (webSocket &&
                    !h3.canConnectProtocol(target)
                ) {
                    tcp(data, callContext, ProtocolReason.WebSocket, d)
                } else {
                    raced(target, data, callContext, network, emptyList(), d)
                }
            }

            else -> {
                auto(data, callContext, target, webSocket, network, d)
            }
        }
    }

    /** Warns about a throwing `http3Allowed` at most once per 5 minutes; internal for tests (its clock). */
    internal val http3SwitchWarning =
        RateLimitedWarning(
            5.minutes,
            io.kuicksilver.ktor.client.h1
                .monotonicMillis(),
        )

    /**
     * `http3Allowed`, failing open: a switch that throws an Exception allows HTTP/3 (a broken remote configuration must not
     * break traffic). A CancellationException and an Error go to the caller: the call is being cancelled, or the VM is in
     * trouble, neither of which is the switch's answer. Also used by `webTransport`.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    internal fun http3Allowed(): Boolean =
        try {
            config.http3.http3Allowed()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (http3SwitchWarning.tryAcquire()) {
                runCatching {
                    val logger = events.logger
                    if (logger.isEnabled(LogLevel.Warn)) {
                        logger.log(LogLevel.Warn, "http3Allowed threw; HTTP/3 stays allowed (reported at most once per 5 minutes)", e)
                    }
                }
            }
            true
        }

    /** `HttpClient.closeHttp3Connections()`: GOAWAY on every HTTP/3 connection and WebTransport session ([H3Pool.goAwayAll]). */
    internal suspend fun closeHttp3Connections() = h3.goAwayAll(engineScope)

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
        d: ProtocolDiagnostics,
    ): HttpResponseData {
        val origin = originKey(data.url)
        val alt = "${t.host}:${t.port}"
        // one resolution for both sides of the race and a fallback after it (RFC 8305 section 3)
        val dns = config.newRequestDns()
        val (broken, confirmed, rtt) =
            altSvcLock.withLock {
                Triple(brokenAltSvc.brokenReason(origin, alt), brokenAltSvc.quicConfirmedOn(network), srtt[origin])
            }
        if (broken != null) {
            d.brokenSince = broken
            return tcp(data, callContext, ProtocolReason.BrokenAlternative, d, dns = dns)
        }
        // an established HTTP/3 connection is used as is: the race is about setting one up
        if (h3.existing(t) != null) {
            selected(data, HttpProtocolVersion.HTTP_3_0, ProtocolReason.ExistingConnection, d)
            return h3WithFallback(t, data, callContext, d, extraHeaders, dns)
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
                (it as? H1Pool.Opened)?.let { o -> h1.recycle(o) } // unused: back to the pool, or its HTTP/2 stream given back
            })
        // the TCP side is HTTP/2 when the server picked h2 in ALPN
        val winner =
            when {
                result.winner == Protocol.H3 -> HttpProtocolVersion.HTTP_3_0
                (result.value as H1Pool.Opened).h2 != null -> HttpProtocolVersion.HTTP_2_0
                else -> HttpProtocolVersion.HTTP_1_1
            }
        val headStart = race.headStart(rtt, confirmed)
        events.emit("raceEnded") { raceEnded(data, winner, headStart, result.h3Failure) }
        d.raced(headStart)
        if (result.winner == Protocol.H1) {
            // HTTP/3 failed first, or had not answered yet when HTTP/1.1 was ready
            d.h3Failure = result.h3Failure
            d.fallback = classifyH3Failure(result.h3Failure) ?: FallbackReason.H3NotReady
        }
        if (result.winner == Protocol.H3) selected(data, winner, ProtocolReason.Race, d) // the TCP side: once its exchange starts
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
                h3WithFallback(t, data, callContext, d, extraHeaders, dns, prefer = conn)
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
                            } else if (outcome !is CancellationException && !isTransientRefusal(outcome)) {
                                // a refusal (CONNECTION_REFUSED) is no failure of the alternative: the next call tries it again
                                brokenAltSvc.markBroken(origin, alt, classifyH3Failure(outcome) ?: FallbackReason.Other)
                                events.emit("altSvcMarkedBroken") { altSvcMarkedBroken(origin, alt) }
                            }
                        }
                    }
                }
                tcp(data, callContext, ProtocolReason.Race, d, result.value as H1Pool.Opened, dns)
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
            "client.h2Connections" to h1.h2.connectionCount.toLong(),
            "client.h2Streams" to h1.h2.streamCount.toLong(),
            "client.h2Routes" to h1.h2.routeCount.toLong(),
            "client.h2Refused" to h1.h2Refused.size.toLong(),
            "client.h3Connections" to h3.connectionsForProbe().toLong(),
            "client.h3Dedicated" to h3.dedicatedCount.value.toLong(),
            "client.brokenAltSvc" to broken.toLong(),
            "client.srtt" to rtts.toLong(),
        )
    }

    /** The origins with a remembered RTT (tests). */
    internal val srttOrigins: Int get() = srtt.size

    /** Whether an HTTP/3 connection to the origin of [url] is open (tests). */
    internal suspend fun hasH3Connection(url: io.ktor.http.Url): Boolean = h3.existing(H3Target(url.host, url.host, url.port)) != null

    private fun originKey(url: io.ktor.http.Url): String = originKeyOf(url)

    /**
     * `Auto` (RFC 7838): HTTP/3 to a live alternative the origin announced, with `Alt-Used`; otherwise HTTP/1.1,
     * learning `Alt-Svc` from its responses (always over verified TLS here: the engine's TLS rejects what the trust
     * configuration rejects). A 421 from the alternative drops that alternative, the origin's others stay (RFC 7838
     * section 6), and the request goes to the origin over HTTP/1.1.
     */
    private suspend fun auto(
        data: HttpRequestData,
        callContext: CoroutineContext,
        origin: H3Target,
        webSocket: Boolean,
        network: String?,
        d: ProtocolDiagnostics,
    ): HttpResponseData {
        val url = data.url
        val alt = altSvcUpdate { altSvc.h3For(url) }
        var misdirected = false
        if (alt != null) {
            val altHost = alt.host ?: url.host
            val t = H3Target(url.host, altHost, alt.port)
            d.alternative(altHost, alt.port, AlternativeSource.AltSvc)
            if (!webSocket || h3.canConnectProtocol(t)) {
                events.emit("altSvcUsed") { altSvcUsed(data, "${uriHost(altHost)}:${alt.port}") }
                val r = raced(t, data, callContext, network, listOf("alt-used" to "${uriHost(altHost)}:${alt.port}"), d)
                // the origin's Alt-Svc on any answer, over HTTP/3 as over HTTP/1.1 (broken alternative, lost race, fallback): a
                // new list or `clear` replaces the cached one (RFC 7838 section 3); a 421 is not authoritative and changes
                // nothing (RFC 9110 section 15.5.20), except that one from the alternative removes it (below, RFC 7838 section 6)
                altSvcUpdate {
                    altSvc.onResponse(
                        url,
                        r.statusCode.value,
                        r.headers.getAll("Alt-Svc").orEmpty(),
                        verifiedTls = url.protocol.isSecure(),
                    )
                }
                if (r.statusCode.value != 421 || r.version != HttpProtocolVersion.HTTP_3_0) return r
                altSvcUpdate { altSvc.removeAlternative(url, alt) }
                if (!data.body.isReplayable()) {
                    throw H3BodyConsumed(
                        "421 Misdirected Request from the alternative, and the request body was already consumed",
                    )
                }
                d.attempts++ // the alternative's 421 was one; the origin over HTTP/1.1 is the next
                misdirected = true
            }
        }
        val r =
            tcp(
                data,
                callContext,
                // after the alternative's 421 it is gone: no alternative, whatever the request (a WebSocket included)
                if (alt != null && webSocket && !misdirected) ProtocolReason.WebSocket else ProtocolReason.NoAlternative,
                d,
            ) { if (misdirected && d.fallback != FallbackReason.H2Refused) d.fallback = FallbackReason.MisdirectedRequest }
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
        d: ProtocolDiagnostics,
        extraHeaders: List<Pair<String, String>> = emptyList(),
        dns: RequestDns = config.newRequestDns(),
        prefer: io.kuicksilver.http3.Http3Connection? = null, // the race's connection, used even if since retired
    ): HttpResponseData =
        try {
            h3.execute(target, data, callContext, extraHeaders, dns, prefer)
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (
            e: H3NotSent,
        ) {
            fallbackToH1(target, data, callContext, e, dns, d)
        } catch (
            e: Throwable,
        ) {
            if (data.method.isIdempotent() && (e is QuicException || e is Http3Exception) &&
                data.body.isReplayable()
            ) {
                fallbackToH1(target, data, callContext, e, dns, d)
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
        d: ProtocolDiagnostics,
    ): HttpResponseData {
        val cause = if (h3Failure is H3NotSent) h3Failure.cause ?: h3Failure else h3Failure
        events.emit("fallback") { fallback(data, cause) }
        // HTTP/1.1 is one more attempt only when HTTP/3 tried the request (H3NotSent: it never reached a stream, except
        // after the repeats the server did not process, which were attempts)
        if (h3Failure !is H3NotSent || h3Failure.cause is Http3Exception.RequestNotProcessed) d.attempts++
        d.h3Failure = cause
        val reason = classifyH3Failure(cause) ?: FallbackReason.Other
        d.fallback = reason
        val r = tcp(data, callContext, ProtocolReason.Fallback, d, dns = dns)
        if (marksAlternativeBroken(h3Failure)) {
            val origin = originKey(data.url)
            val alt = "${target.host}:${target.port}"
            altSvcLock.withLock { brokenAltSvc.markBroken(origin, alt, reason) }
            d.markedBroken = true
            events.emit("altSvcMarkedBroken") { altSvcMarkedBroken(origin, alt) }
        }
        return r
    }

    override fun toString(): String = "Kuicksilver"
}

/**
 * Whether an HTTP/3 failure says the alternative itself does not work (RFC 7838 section 2.4): the connection could not be
 * set up (handshake, transport) or failed as a whole. A single stream's reset, a malformed message, a refused request
 * and a field section refused locally are about one exchange and leave the alternative usable, and so does a server's
 * CONNECTION_REFUSED ([isTransientRefusal]).
 */
internal fun marksAlternativeBroken(e: Throwable): Boolean =
    if (isTransientRefusal(e)) {
        false
    } else {
        when (e) {
            is H3NotSent -> e.cause !is Http3Exception.RequestNotProcessed
            is QuicException.StreamError -> false
            is QuicException -> true
            is Http3Exception.Protocol -> e.streamId == null
            is Http3Exception.Qpack, is Http3Exception.Settings -> true
            else -> false
        }
    }

/**
 * Whether an HTTP/3 failure is the server refusing a new connection for now: a CONNECTION_CLOSE from the peer with
 * CONNECTION_REFUSED (RFC 9000 section 20.1), which a server sends when it cannot take the client (section 5.2.2: a full
 * accept queue, `Drain`, a stop; also quic-go's `sendConnectionRefused` and quinn's `refuse`). That says nothing against
 * the alternative, which stays valid (RFC 7838 sections 2.2 and 3): the call falls back to HTTP/1.1 like one HTTP/3 was
 * not ready for ([FallbackReason.H3NotReady]), and the alternative is not marked broken, so the next call tries HTTP/3
 * again (another instance behind the same address may take it) instead of waiting out 5 minutes to 2 days.
 */
internal fun isTransientRefusal(e: Throwable): Boolean {
    val failure = if (e is H3NotSent) e.cause ?: e else e
    return failure is QuicException.ConnectionLost.TransportClosed &&
        failure.initiator == Initiator.Peer &&
        failure.code == TransportError.CONNECTION_REFUSED
}

/** RFC 9110 section 9.2.2. */
internal fun HttpMethod.isIdempotent(): Boolean =
    this in setOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options, HttpMethod.Put, HttpMethod.Delete, HttpMethod("TRACE"))
