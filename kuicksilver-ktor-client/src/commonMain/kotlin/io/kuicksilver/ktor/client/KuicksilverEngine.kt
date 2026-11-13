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
import io.kuicksilver.ktor.client.dns.AliasProgress
import io.kuicksilver.ktor.client.dns.HTTPS_DEFAULT_ALPN
import io.kuicksilver.ktor.client.dns.HttpsEndpoint
import io.kuicksilver.ktor.client.dns.HttpsRecords
import io.kuicksilver.ktor.client.dns.HttpsResolution
import io.kuicksilver.ktor.client.dns.httpsQueryName
import io.kuicksilver.ktor.client.h1.H1Pool
import io.kuicksilver.ktor.client.h1.monotonicMillis
import io.kuicksilver.ktor.client.h3.H3ClosedAfterGoAwayKey
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
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.CoroutineContext
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

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

    init {
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val extraWait = config.http3.httpsRecordExtraWait
        // RFC 9460 section 5.1: "Clients implementing this optimization SHOULD wait for 50 milliseconds"
        require(extraWait >= MIN_HTTPS_RECORD_EXTRA_WAIT && extraWait <= MAX_HTTPS_RECORD_EXTRA_WAIT) {
            "httpsRecordExtraWait must be 50 ms..1 s, was $extraWait"
        }
        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
        val wsLimit = config.webSocketMaxMessageSize
        require(wsLimit >= 1) { "webSocketMaxMessageSize must be at least 1, was $wsLimit" }
    }

    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private val selector = engineSelector(dispatcher) // a socket closed on it is released at once (EngineSelector.kt)
    private val engineJob = SupervisorJob(coroutineContext[Job])

    /** Background work that outlives a call (a QUIC setup that lost the race); completed by [close] so the cleanup can run. */
    private val engineScope = CoroutineScope(coroutineContext + engineJob)

    /**
     * The networks `connectionMigration` follows ([Http3ConnectionMigration.networks]), the engine's network while `networkId`
     * is not set; null when there is no such source.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val followedNetworks: kotlinx.coroutines.flow.Flow<Any?>? =
        if (config.http3.networkIdSet) null else config.http3.connectionMigration?.networks

    /** The last network [followedNetworks] reported (`toString()`), once it reported one ([followedNetworkKnown]). */
    @kotlin.concurrent.Volatile
    private var followedNetwork: String? = null

    @kotlin.concurrent.Volatile
    private var followedNetworkKnown = false

    /** Completed by the first value of [followedNetworks], or by its end: requests wait a moment for it ([checkNetwork]). */
    private val firstFollowedNetwork = kotlinx.coroutines.CompletableDeferred<Unit>()

    /**
     * Until when requests wait for [firstFollowedNetwork]: [FIRST_NETWORK_WAIT] after the engine was created, one deadline
     * for all of them (a source that says nothing, offline or without replay, delays no request past it). Internal for tests.
     */
    internal var firstNetworkDeadline: kotlin.time.TimeMark =
        kotlin.time.TimeSource.Monotonic
            .markNow() + FIRST_NETWORK_WAIT

    /** Requests that waited for [firstFollowedNetwork]; internal for tests. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val firstNetworkWaits = kotlin.concurrent.atomics.AtomicInt(0)

    /** How many values of [followedNetworks] the engine has processed; internal for tests. */
    internal val followedNetworkUpdates = kotlinx.coroutines.flow.MutableStateFlow(0)

    /**
     * The HTTPS record lookups (`http3.httpsRecords`, RFC 9460), null when off; a lookup lives at most the connect timeout
     * (30 s when that is longer), so a resolver that never answers holds nothing for long. Internal for tests.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    internal val httpsRecordsForTest: HttpsRecords? =
        minOf(config.connectTimeout, MAX_HTTPS_RECORD_QUERY).let { timeout ->
            config.http3.httpsRecords
                .lookup(timeout)
                // RFC 9460 section 12: answers are cached only where a network change can be seen (networkId, or the
                // networks connectionMigration follows). TTLs run on an ExpiryClock: neither a wall clock stepped back nor a
                // device that slept keeps a record past its TTL
                ?.let {
                    HttpsRecords(
                        it,
                        engineScope,
                        timeout,
                        ExpiryClock(),
                        caching =
                            followedNetworks != null || config.http3.networkIdSet,
                    )
                }
        }
    private val httpsRecords: HttpsRecords? get() = httpsRecordsForTest

    /** The [KuicksilverEventListener] of the configuration, behind a guard that never fails a call. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private val events = EngineEvents(config.eventListener, config.logger ?: config.http3.endpoint.logger)

    /**
     * The jobs that let HTTP/3 connections follow the network (`http3.connectionMigration`): outside the requests' job, so
     * a closed client's calls still migrate while they finish, and cancelled by the cleanup before the connections close.
     * Internal for tests.
     */
    internal val migrationJob = SupervisorJob()

    /** Where [migrationJob]'s work runs; a failure that escapes a migrator is logged, never thrown at the application. */
    private val migrationScope =
        CoroutineScope(
            dispatcher + migrationJob + CoroutineName("kuicksilver-h3-migration") +
                CoroutineExceptionHandler { _, e ->
                    runCatching {
                        if (events.logger.isEnabled(LogLevel.Warn)) events.logger.log(LogLevel.Warn, "connection migration failed", e)
                    }
                },
        )

    /** `proxyResolver`'s answers per route ([proxyFor]). */
    internal val proxies = ProxyRouting(config, events.logger)
    internal val h1 = H1Pool(config, selector, events, altSvcFrame = ::onAltSvcFrame) // internal for tests (the engine's session cache)

    // internal for tests (0-RTT reconnects); one WebSocket CONNECTING per host over HTTP/1.1 and HTTP/3 together
    internal val h3 = H3Pool(config, events, migrationScope = migrationScope, webSocketConnecting = h1.webSocketConnecting)
    private val altSvc = AltSvcCache(config.http3.altSvcStore) { getTimeMillis() }
    private val altSvcLock = Mutex()

    /** Serializes [FileAltSvcStore] writes, which run after [altSvcLock] is released; internal for tests. */
    internal val altSvcWriteLock = Mutex()

    /** Broken alternatives and networks where QUIC worked; internal for tests. */
    internal val brokenAltSvc = BrokenAltSvc(monotonicMillis(), ::getTimeMillis) // ends on either: wall steps, deep sleep
    private val race = ProtocolRace(config.http3.hardDelay)
    private val srtt = LinkedHashMap<String, kotlin.time.Duration>() // per origin, from the last HTTP/3 connection; LRU-bounded
    private var lastNetwork: String? = null
    private var networkSeen = false

    /** The cleanup that runs once every request finished after [close]; internal so a test can wait for it. */
    internal val cleanup: Job

    /** Closes expired idle connections of both pools and prunes their bookkeeping; cancelled by [close]. */
    private val reaper: Job = engineScope.launch(CoroutineName("kuicksilver-pool-reaper")) { reapIdleConnections(h1, h3, config) }

    init {
        followedNetworks?.let { networks ->
            migrationScope.launch(CoroutineName("kuicksilver-network-follower")) {
                var failure: Exception? = null
                try {
                    networks.collect { n ->
                        followedNetwork = n?.toString()
                        followedNetworkKnown = true
                        try {
                            checkNetwork()
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            // the store failed (an application's own AltSvcStore): this change is lost, the next is followed
                            runCatching {
                                if (events.logger.isEnabled(LogLevel.Warn)) {
                                    events.logger.log(LogLevel.Warn, "a network change could not be applied to the Alt-Svc store", e)
                                }
                            }
                        }
                        // RFC 9460 section 12: "Clients MUST ensure that their DNS cache is partitioned for each local network,
                        // or flushed on network changes": every update the source reports flushes it, also one whose value
                        // equals the last (an update of the network that the value does not tell apart); the Alt-Svc rule
                        // above (RFC 7838 section 2.2) looks at changed values only
                        httpsRecords?.onNetworkChanged()
                        firstFollowedNetwork.complete(Unit)
                        followedNetworkUpdates.value++
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    failure = e
                }
                // the source failed (on Android, no more network callbacks) or ended: the engine no longer sees network
                // changes, so it keeps no HTTPS records of its own any more (RFC 9460 section 12)
                followedNetworkKnown = false
                firstFollowedNetwork.complete(Unit)
                httpsRecords?.stopCaching()
                runCatching {
                    if (events.logger.isEnabled(LogLevel.Info)) {
                        events.logger.log(
                            LogLevel.Info,
                            "the network source of connectionMigration ${if (failure != null) "failed" else "ended"}; " +
                                "network changes are no longer seen",
                            failure,
                        )
                    }
                }
                followedNetworkUpdates.value++
            }
        }
        val requests = coroutineContext[Job]!!
        cleanup =
            GlobalScope.launch(super.coroutineContext, start = CoroutineStart.ATOMIC) {
                try {
                    requests.join()
                } finally {
                    withContext(NonCancellable) { altSvcUpdate {} } // a snapshot no request took (an expiry dropped on lookup)
                    h1.closeAll()
                    migrationJob.cancel() // the migrators end before their connections
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
        httpsRecords?.close() // a DNS lookup still running would hold up the cleanup for up to its timeout
        engineJob.complete()
        super.close()
    }

    /** Tests: runs between [execute]'s first closed check and the attach of the call to the requests' job. */
    internal var beforeCallAttachForTest: (suspend () -> Unit)? = null

    override suspend fun execute(data: HttpRequestData): HttpResponseData {
        // the requests' job stays active while calls finish after close(), so Ktor's own closed check lets new calls in
        if (closed) throw ClientEngineClosedException()
        beforeCallAttachForTest?.invoke()
        val callContext = callContext()
        // Ktor's call job is not a child of the requests' job: a child of that job lives as long as the call (its response
        // body included), so the cleanup after close() waits for the call (as CIO's) instead of closing its socket under it
        val inFlight = Job(this.coroutineContext[Job])
        callContext[Job]!!.invokeOnCompletion { inFlight.complete() }
        // a close() since the check above may have completed the requests' job before the attach: the cleanup then does not
        // wait for this call and closes the pools under it (the HTTP/3 pool failed it with IllegalStateException, a TCP
        // connect on the closed selector with an IOException). close() sets the flag first, so it is seen here
        if (closed) {
            inFlight.complete()
            throw ClientEngineClosedException()
        }
        events.emit("callStart") { callStart(data) }
        // a new one per call, also when the request's attributes came with one (a redirect or a retry copies them): the
        // pools count their retries in it, and the response hands it out
        val diagnostics = ProtocolDiagnostics()
        data.attributes.put(KuicksilverDiagnosticsKey, diagnostics)
        data.attributes.remove(NeverIndexedReceivedKey) // a redirect or a retry copies the previous response's
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
                    ProtocolReason.Race, ProtocolReason.Fallback, ProtocolReason.ExistingConnection,
                    ProtocolReason.HttpsRecord,
                    -> d.fallback
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
        // RFC 9460 section 9.5: an http request first asks for the HTTPS records of its https URL (not through a proxy:
        // section 3.2, the engine does no SVCB resolution there)
        val records = httpsRecords
        var upgradeDns: RequestDns? = null // the origin's addresses, looked up while the records were
        if (records != null && url.protocol == io.ktor.http.URLProtocol.HTTP && !isIpLiteral(url.host) && proxyFor(url) == null) {
            // a new network first (section 12, MUST): the decision must not rest on the old network's records
            checkNetwork()
            upgradeDns = config.newRequestDns()
            httpsUpgrade(records, data, callContext, upgradeDns)?.let { return it }
        }
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
            // no Alt-Svc is used or learned through a proxy
            val r = tcp(data, callContext, reason, d, dns = upgradeDns ?: config.newRequestDns(), proxy = proxy)
            // switched off, Auto keeps learning Alt-Svc, so switching back needs no warm-up
            if (disabled && proxy == null && config.http3.discovery == Http3DiscoveryMode.Auto) {
                learnAltSvc(url, r, verifiedTls = true)
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

    /**
     * `HttpClient.clearAlternativeServices(origin)` (RFC 7838 section 9.4): the cached alternatives, broken marks and RTT of
     * the origin of [origin], or of every origin; the store's file is written before this returns.
     */
    internal suspend fun clearAlternativeServices(origin: io.ktor.http.Url?): Boolean {
        val key = origin?.let(::originKey)
        val complete =
            altSvcUpdate {
                brokenAltSvc.clear(key)
                if (key == null) srtt.clear() else srtt.remove(key)
                altSvc.clear(key)
            }
        if (!complete) {
            runCatching {
                if (events.logger.isEnabled(LogLevel.Warn)) {
                    events.logger.log(
                        LogLevel.Warn,
                        "clearAlternativeServices: the AltSvcStore does not implement clear(); the origins seen since the client " +
                            "started were removed, entries of other origins it kept from earlier may remain (RFC 7838 section 9.4)",
                        null,
                    )
                }
            }
        }
        return complete
    }

    /**
     * A new network (`networkId`, else the networks `connectionMigration` follows) forgets broken marks, QUIC confirmation,
     * the HTTPS records, the NAT64 prefixes ([Nat64]), the kept name lookups and, if asked, non-persistent alternatives (RFC
     * 7838 section 2.2). The first network the engine sees
     * is compared with the one the store's entries were learned on ([AltSvcStore.networkId], kept across restarts by
     * [FileAltSvcStore]) when it comes from `networkId`. A network of the followed source has no identity that is stable
     * across restarts (an Android network handle is a number the system reuses, an Apple path key an interface), so it is
     * never stored: at its first value the engine takes the network as changed, as it does for what it learned before that
     * value came (requests wait for it until [firstNetworkDeadline], one deadline for all). Without either source the engine knows no network: null,
     * and nothing is compared.
     */
    private suspend fun checkNetwork(): String? {
        if (!config.http3.networkIdSet) {
            if (followedNetworks == null) return null
            if (!followedNetworkKnown && !firstFollowedNetwork.isCompleted) {
                val left = -firstNetworkDeadline.elapsedNow()
                if (left.isPositive()) {
                    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
                    firstNetworkWaits.addAndFetch(1)
                    withTimeoutOrNull(left) { firstFollowedNetwork.await() }
                }
            }
            if (!followedNetworkKnown) return null
        }
        var changed = false
        val network =
            altSvcUpdate {
                val fromNetworkId = config.http3.networkIdSet
                val id = if (fromNetworkId) config.http3.networkId() else followedNetwork
                if (networkSeen) {
                    if (id != lastNetwork) {
                        brokenAltSvc.onNetworkChanged()
                        altSvc.onNetworkChanged(config.http3.clearOnNetworkChange)
                        changed = true
                    }
                } else if (!fromNetworkId || id != altSvc.network) {
                    // learned on another network, on one nobody recorded, or before the followed source said which one
                    // (RFC 7838 section 3.1: "cached alternative services will be cleared when the client detects a network
                    // change"); the HTTPS records kept meanwhile go too
                    altSvc.onNetworkChanged(config.http3.clearOnNetworkChange)
                    changed = !fromNetworkId
                }
                networkSeen = true
                lastNetwork = id
                if (fromNetworkId) altSvc.network = id
                id
            }
        if (changed) {
            httpsRecords?.onNetworkChanged()
            Nat64.system.reset() // RFC 7050 section 3: the new network's Pref64::/n is discovered when needed
            @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
            io.kuicksilver.ktor.network
                .clearLookupCache() // the old network's resolver answered those
        }
        return network
    }

    /** One received ALTSVC frame waiting to be learned: [seq] orders it among all frames of this engine. */
    private class PendingAltSvcFrame(
        val url: io.ktor.http.Url,
        val value: String,
        val seq: Long,
    )

    /**
     * The latest ALTSVC frame per origin not yet learned (at most [AltSvcCache.MAX_ORIGINS] origins, the eldest dropped):
     * a newer frame for an origin replaces the one waiting, so a flood holds one value per origin, not one per frame.
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val pendingAltSvcFrames = kotlin.concurrent.atomics.AtomicReference<Map<String, PendingAltSvcFrame>>(emptyMap())

    /** Whether the one coroutine that learns [pendingAltSvcFrames] runs. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val altSvcFrameLearner = kotlin.concurrent.atomics.AtomicBoolean(false)

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val altSvcFrameSeq = kotlin.concurrent.atomics.AtomicLong(0)

    /** The sequence number of the last ALTSVC frame received ([onAltSvcFrame]); internal for tests. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val altSvcFramesReceived: Long get() = altSvcFrameSeq.load()

    /** The sequence number up to which ALTSVC frames are learned (or superseded by a later one); internal for tests. */
    internal val altSvcFramesApplied = kotlinx.coroutines.flow.MutableStateFlow(0L)

    /** ALTSVC frames waiting to be learned; internal for tests. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val altSvcFramesWaiting: Int get() = pendingAltSvcFrames.load().size

    /**
     * An ALTSVC frame (RFC 7838 section 4) from an HTTP/2 connection to the origin of [url]: learned as an `Alt-Svc` header
     * of a response is, in [Http3DiscoveryMode.Auto] (the mode that learns), and never through a proxy (the pool passes none).
     * Called on the connection's reader without blocking: the frame waits in [pendingAltSvcFrames], replacing an older one
     * of its origin, and one coroutine learns the waiting frames in order, so the last frame an origin sent is the one that
     * holds (an `h3` then a `clear` ends cleared) and a flood costs no more than one value per origin. Internal for tests.
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal fun onAltSvcFrame(
        url: io.ktor.http.Url,
        value: String,
    ) {
        if (config.http3.discovery != Http3DiscoveryMode.Auto) return
        val origin = originKey(url)
        while (true) {
            val m = pendingAltSvcFrames.load()
            val next = LinkedHashMap(m)
            next.remove(origin)
            next[origin] = PendingAltSvcFrame(url, value, altSvcFrameSeq.addAndFetch(1))
            next.evictEldest(AltSvcCache.MAX_ORIGINS)
            if (pendingAltSvcFrames.compareAndSet(m, next)) break
        }
        if (altSvcFrameLearner.compareAndSet(false, true)) {
            engineScope.launch(CoroutineName("kuicksilver-altsvc-frames")) { learnAltSvcFrames() }
        }
    }

    /** The one learner of [pendingAltSvcFrames]: takes them all, learns them in order of arrival, until none waits. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private suspend fun learnAltSvcFrames() {
        var done = false
        try {
            while (true) {
                val batch = pendingAltSvcFrames.exchange(emptyMap())
                if (batch.isEmpty()) {
                    altSvcFrameLearner.store(false)
                    done = true
                    // a frame that came after the exchange and found the learner still marked running is taken here
                    if (pendingAltSvcFrames.load().isEmpty() || !altSvcFrameLearner.compareAndSet(false, true)) return
                    done = false
                    continue
                }
                val frames = batch.values.sortedBy { it.seq }
                val failures = ArrayList<Exception>()
                altSvcUpdate {
                    for (f in frames) {
                        // a store that throws (an application's own) loses this frame, not the ones after it
                        try {
                            altSvc.onAltSvcFrame(f.url, f.value)
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Exception) {
                            failures += e
                        }
                    }
                }
                failures.firstOrNull()?.let { e ->
                    runCatching {
                        if (events.logger.isEnabled(LogLevel.Warn)) {
                            events.logger.log(LogLevel.Warn, "${failures.size} ALTSVC frame(s) could not be stored", e)
                        }
                    }
                }
                altSvcFramesApplied.value = maxOf(altSvcFramesApplied.value, frames.last().seq)
            }
        } finally {
            // cancelled or failed: the next frame starts a learner again
            if (!done) altSvcFrameLearner.store(false)
        }
    }

    /**
     * Learns the `Alt-Svc` of [r], the response to [url] (RFC 7838 section 3): freshness counts from the response's
     * generation, its `Age` and the time it took (section 3.1, [AltSvcCache.onResponse]).
     */
    private suspend fun learnAltSvc(
        url: io.ktor.http.Url,
        r: HttpResponseData,
        verifiedTls: Boolean,
    ) = altSvcUpdate {
        altSvc.onResponse(
            url,
            r.statusCode.value,
            r.headers.getAll("Alt-Svc").orEmpty(),
            verifiedTls,
            ageValues = r.headers.getAll(HttpHeaders.Age).orEmpty(),
            responseDelayMillis = getTimeMillis() - r.requestTime.timestamp,
        )
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
        // one resolution for both sides of the race and a fallback after it (RFC 8305 section 3)
        dns: RequestDns = config.newRequestDns(),
        // the TCP side's: an HTTPS record's endpoint (RFC 9460 section 3) instead of the origin's addresses
        tcpDns: RequestDns = dns,
        // a failure to set up any connection is EndpointUnreachable: the next endpoint of the records is tried
        setupFailures: Boolean = false,
    ): HttpResponseData {
        val origin = originKey(data.url)
        val alt = "${t.host}:${t.port}"
        val (broken, confirmed, rtt) =
            altSvcLock.withLock {
                Triple(brokenAltSvc.brokenReason(origin, alt), brokenAltSvc.quicConfirmedOn(network), srtt[origin])
            }
        if (broken != null) {
            d.brokenSince = broken
            val opened = if (setupFailures) openOrUnreachable(data, tcpDns) else null
            return tcp(data, callContext, ProtocolReason.BrokenAlternative, d, opened, tcpDns)
        }
        // an established HTTP/3 connection is used as is: the race is about setting one up
        if (h3.existing(t) != null) {
            selected(data, HttpProtocolVersion.HTTP_3_0, ProtocolReason.ExistingConnection, d)
            return h3WithFallback(t, data, callContext, d, extraHeaders, dns, tcpDns = tcpDns)
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
            try {
                race.race<Any>({ h3Attempt.await() }, { h1.open(data, tcpDns) }, rtt, confirmed, onLoser = {
                    (it as? H1Pool.Opened)?.let { o -> h1.recycle(o) } // unused: back to the pool, or its HTTP/2 stream given back
                })
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (!setupFailures) throw e
                settleLostQuic(h3Attempt, network, origin, alt) // both failed: QUIC's failure still marks the endpoint broken
                throw EndpointUnreachable(e)
            }
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
                h3WithFallback(t, data, callContext, d, extraHeaders, dns, prefer = conn, tcpDns = tcpDns)
            }

            Protocol.H1 -> {
                settleLostQuic(h3Attempt, network, origin, alt)
                tcp(data, callContext, ProtocolReason.Race, d, result.value as H1Pool.Opened, tcpDns)
            }
        }
    }

    /** Once the QUIC setup that lost a race is settled: QUIC confirmed on [network], or [alt] of [origin] marked broken. */
    private fun settleLostQuic(
        h3Attempt: kotlinx.coroutines.Deferred<io.kuicksilver.http3.Http3Connection>,
        network: String?,
        origin: String,
        alt: String,
    ) {
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
                raceLoserSettledForTest?.invoke()
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

    /** Called once the HTTP/3 setup that lost a race is settled: QUIC confirmed, the alternative marked broken, or neither (tests). */
    internal var raceLoserSettledForTest: (() -> Unit)? = null

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
        val originKey = originKey(url)
        // a broken alternative is passed over for the next fresh one (RFC 7838 section 2.4)
        val alt = altSvcUpdate { altSvc.h3For(url) { brokenAltSvc.brokenReason(originKey, "${it.host ?: url.host}:${it.port}") == null } }
        // the origin's HTTPS records (RFC 9460), when looked up: SVCB resolution decides where to connect (section 3)
        val records = httpsRecords
        if (records != null && !isIpLiteral(url.host)) return autoWithRecords(data, callContext, webSocket, network, d, records, alt)
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
                learnAltSvc(url, r, verifiedTls = url.protocol.isSecure())
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
        learnAltSvc(url, r, verifiedTls = url.protocol.isSecure())
        return r
    }

    /**
     * RFC 9460 section 9.5 for an `http` [data]: the `https` URL is the same one with the scheme replaced and port 80 made
     * 443; when the HTTPS records of that URL have an AliasMode or a compatible ServiceMode record, the answer is a 307
     * (Temporary Redirect) to it, made here without any connection, which Ktor's `HttpRedirect` follows as it follows a
     * 307 from a server, and a client without it sees. It carries no more trust than a cleartext 307 (section 9.5, MUST
     * NOT): nothing is remembered beyond the records' TTL. Null to go on over http (no records, or a failed lookup over
     * plain DNS); a failed lookup over protected DNS abandons the request (section 3.1).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, InternalAPI::class)
    private suspend fun httpsUpgrade(
        records: HttpsRecords,
        data: HttpRequestData,
        callContext: CoroutineContext,
        dns: RequestDns,
    ): HttpResponseData? {
        val url = data.url
        val https =
            io.ktor.http
                .URLBuilder(url)
                .apply {
                    protocol = io.ktor.http.URLProtocol.HTTPS
                    port = if (url.specifiedPort == 0 || url.specifiedPort == 80) io.ktor.http.DEFAULT_PORT else url.specifiedPort
                }.build()
        val secure = config.http3.httpsRecords.isSecure()
        // waited for as before an https request: while the origin's addresses resolve and the extra wait after them
        // (section 5.1), all of it for a secure source (section 3.1); an answer that comes later is cached for the next
        val upgrade =
            withTimeoutOrNull(config.connectTimeout) {
                coroutineScope {
                    val query = async { records.upgradesToHttps(https.host, https.port, supportedAlpn(webSocket = false)) }
                    val addresses = records.background { lookupQuietly(dns, url.host, url.port) }
                    select {
                        query.onJoin {}
                        addresses.onJoin {}
                    }
                    if (secure) {
                        query.join()
                    } else if (!query.isCompleted) {
                        withTimeoutOrNull(config.http3.httpsRecordExtraWait) { query.join() }
                    }
                    val answer =
                        if (query.isCompleted && !query.isCancelled) {
                            query.getCompleted()
                        } else if (secure) {
                            null
                        } else {
                            false
                        }
                    query.cancel()
                    answer
                }
            } ?: if (secure) null else false
        if (upgrade == null && secure) {
            throw kotlinx.io.IOException(
                "the HTTPS records of ${https.host} could not be resolved over the secure DNS source before an http request: " +
                    "the request is abandoned (RFC 9460 sections 3.1 and 9.5)",
            )
        }
        if (upgrade != true) return null
        return HttpResponseData(
            io.ktor.http.HttpStatusCode.TemporaryRedirect,
            io.ktor.util.date
                .GMTDate(),
            io.ktor.http.headersOf(HttpHeaders.Location, https.toString()),
            HttpProtocolVersion.HTTP_1_1,
            io.ktor.utils.io.ByteReadChannel.Empty,
            callContext,
        )
    }

    /** One connection attempt of [autoWithRecords]: QUIC to [h3] and TCP to [tcp] (the origin itself with [tcpToOrigin]). */
    private class Attempt(
        val h3: HttpsEndpoint?,
        val tcp: HttpsEndpoint?,
        val tcpToOrigin: Boolean,
        /** [h3] is an Alt-Svc alternative (with `Alt-Used`), not an endpoint of the origin's records. */
        val altSvc: Boolean,
        /** [h3] or [tcp] came from the origin's HTTPS records. */
        val fromRecords: Boolean,
    )

    /**
     * `Auto` with HTTPS records (RFC 9460 sections 3 and 9): SVCB resolution of the origin gives the endpoints, tried in
     * order with fallback to the next when one cannot be connected to (section 3: "Clients SHOULD try higher-priority
     * alternatives first, with fallback to lower-priority alternatives"); each over the transports its ALPN set allows,
     * QUIC and TCP racing as for an alternative (section 7.1.2), TCP to the endpoint's TargetName and port, TLS and the
     * request naming the origin (sections 2.3 and 9.1, MUST). When they all fail, or there are none, the request goes to the
     * origin as without records (section 3: "the client now attempts to use non-SVCB connection modes"). A cached Alt-Svc
     * alternative comes first, its TCP side going to the origin's first TCP endpoint.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun autoWithRecords(
        data: HttpRequestData,
        callContext: CoroutineContext,
        webSocket: Boolean,
        network: String?,
        d: ProtocolDiagnostics,
        records: HttpsRecords,
        alt: AltSvcEntry?,
    ): HttpResponseData {
        val url = data.url
        val dns = config.newRequestDns()
        val supported = supportedAlpn(webSocket)
        val secure = config.http3.httpsRecords.isSecure()
        val altAuthority = alt?.let { (it.host ?: url.host) to it.port }
        val (origin, altResolution) = awaitResolutions(records, url, dns, supported, secure, altAuthority)
        // the addresses the answers carried for endpoint names: no follow-up query for them (section 5)
        for (r in listOf(origin, altResolution)) (r as? HttpsResolution.Endpoints)?.addresses?.forEach { (h, a) -> dns.seed(h, a) }
        if (origin is HttpsResolution.Failed && secure) {
            // section 3.1: "the client SHOULD abandon its attempt to reach the service, even if the client is SVCB-optional"
            throw kotlinx.io.IOException(
                "the HTTPS records of ${url.host} could not be resolved over the secure DNS source (an error answer, a transport " +
                    "error or a timeout): the request is abandoned (RFC 9460 section 3.1)",
            )
        }
        val originEndpoints =
            when (origin) {
                is HttpsResolution.Endpoints -> origin.endpoints

                // section 3: the AliasMode endpoint is appended "whether successful or not"
                is HttpsResolution.Failed -> listOfNotNull(origin.aliasEndpoint)

                HttpsResolution.None -> emptyList()
            }
        val attempts = ArrayList<Attempt>()
        if (altAuthority != null) {
            // section 9.3: a connection based on a cached Alt-Svc SHOULD be consistent with the alt-authority's HTTPS
            // records: their TargetName and port are used, and only where their ALPN set has h3 (Alt-Svc offers h3 only)
            val asIs = listOf(HttpsEndpoint(altAuthority.first, altAuthority.second, quic = true, tcp = false))
            val altQuic =
                when (altResolution) {
                    is HttpsResolution.Endpoints -> altResolution.endpoints.filter { it.quic }

                    HttpsResolution.None -> asIs

                    // section 3.1: the alternative service is not reached when its protected resolution failed
                    // section 3.1: the alternative service is not reached when its protected resolution failed; after an
                    // AliasMode, the appended endpoint (section 3) is TCP only, so no h3 is consistent with it (section 9.3)
                    is HttpsResolution.Failed -> if (secure) emptyList() else altResolution.aliasEndpoint?.let { emptyList() } ?: asIs
                }
            val firstTcp = originEndpoints.firstOrNull { it.tcp }
            altQuic.forEachIndexed { i, e ->
                attempts += Attempt(e, firstTcp.takeIf { i == 0 }, i == 0 && firstTcp == null, altSvc = true, fromRecords = false)
            }
        }
        for (e in originEndpoints) attempts += Attempt(e.takeIf { it.quic }, e.takeIf { it.tcp }, false, altSvc = false, fromRecords = true)
        val triedQuic = HashSet<String>()
        val triedTcp = HashSet<String>()
        var misdirected = false
        var lastFailure: Throwable? = null
        for (a in attempts) {
            if (misdirected && a.altSvc) continue
            val h3t =
                a.h3
                    ?.takeIf { "${it.host}:${it.port}" !in triedQuic }
                    ?.let { H3Target(url.host, it.host, it.port) }
                    ?.takeIf { !webSocket || h3.canConnectProtocol(it) }
            val tcpKey = if (a.tcpToOrigin) "" else a.tcp?.let { "${it.host}:${it.port}" }
            val tcpDns =
                when {
                    tcpKey == null || tcpKey in triedTcp -> null
                    a.tcpToOrigin -> dns
                    else -> dns.connectTo(a.tcp!!.host, a.tcp.port)
                }
            if (h3t == null && tcpDns == null) continue
            if (h3t != null) triedQuic += "${h3t.host}:${h3t.port}"
            if (tcpDns != null) triedTcp += tcpKey!!
            try {
                val r = attempt(a, h3t, tcpDns, data, callContext, network, d, dns, webSocket, altAuthority)
                learnAltSvc(url, r, verifiedTls = true)
                // a 421 from an Alt-Svc alternative removes it (RFC 7838 section 6); the request goes on without it
                if (!a.altSvc || alt == null || r.statusCode.value != 421 || r.version != HttpProtocolVersion.HTTP_3_0) return r
                altSvcUpdate { altSvc.removeAlternative(url, alt) }
                if (!data.body.isReplayable()) {
                    throw H3BodyConsumed("421 Misdirected Request from the alternative, and the request body was already consumed")
                }
                d.attempts++
                misdirected = true
            } catch (e: EndpointUnreachable) {
                lastFailure = e.cause
            }
        }
        // the non-SVCB connection: the origin over TCP, unless an attempt above already was exactly that
        if ("" in triedTcp) throw lastFailure ?: IllegalStateException("no endpoint of the HTTPS records could be reached")
        val r =
            tcp(
                data,
                callContext,
                if (alt != null && webSocket && !misdirected) ProtocolReason.WebSocket else ProtocolReason.NoAlternative,
                d,
                dns = dns,
            ) { if (misdirected && d.fallback != FallbackReason.H2Refused) d.fallback = FallbackReason.MisdirectedRequest }
        learnAltSvc(url, r, verifiedTls = true)
        return r
    }

    /** One attempt of [autoWithRecords]; a failure to connect, before the request went out, is [EndpointUnreachable]. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun attempt(
        a: Attempt,
        h3t: H3Target?,
        tcpDns: RequestDns?,
        data: HttpRequestData,
        callContext: CoroutineContext,
        network: String?,
        d: ProtocolDiagnostics,
        dns: RequestDns,
        webSocket: Boolean,
        altAuthority: Pair<String, Int>?,
    ): HttpResponseData {
        // Alt-Used names the alt-authority of the Alt-Svc entry (RFC 7838 section 5), not an HTTPS record's TargetName
        val extra =
            if (a.altSvc &&
                altAuthority != null
            ) {
                listOf("alt-used" to "${uriHost(altAuthority.first)}:${altAuthority.second}")
            } else {
                emptyList()
            }
        if (h3t != null) {
            d.alternative(h3t.host, h3t.port, if (a.altSvc) AlternativeSource.AltSvc else AlternativeSource.HttpsRecord)
            if (a.altSvc) events.emit("altSvcUsed") { altSvcUsed(data, "${uriHost(h3t.host)}:${h3t.port}") }
        }
        if (a.fromRecords) {
            val e = a.h3 ?: a.tcp!!
            events.emit("httpsRecordUsed") { httpsRecordUsed(data, "${uriHost(e.host)}:${e.port}") }
        }
        return when {
            h3t != null && tcpDns != null -> {
                raced(h3t, data, callContext, network, extra, d, dns, tcpDns, setupFailures = true)
            }

            h3t != null -> {
                h3Alone(h3t, data, callContext, network, extra, d, dns)
            }

            else -> {
                val opened = openOrUnreachable(data, tcpDns!!)
                tcp(data, callContext, if (webSocket) ProtocolReason.WebSocket else ProtocolReason.HttpsRecord, d, opened, tcpDns)
            }
        }
    }

    /** A TCP connection for [data] through [dns], or [EndpointUnreachable] when none could be set up. */
    private suspend fun openOrUnreachable(
        data: HttpRequestData,
        dns: RequestDns,
    ): H1Pool.Opened =
        try {
            h1.open(data, dns)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            throw EndpointUnreachable(e)
        }

    /**
     * An endpoint of the origin's HTTPS records that offers QUIC only (`no-default-alpn`, RFC 9460 section 7.1.2): HTTP/3
     * there, no TCP. A broken mark, a connection that fails, or a request that HTTP/3 never sent, is [EndpointUnreachable]:
     * the next endpoint is tried.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private suspend fun h3Alone(
        t: H3Target,
        data: HttpRequestData,
        callContext: CoroutineContext,
        network: String?,
        extraHeaders: List<Pair<String, String>>,
        d: ProtocolDiagnostics,
        dns: RequestDns,
    ): HttpResponseData {
        val origin = originKey(data.url)
        val alt = "${t.host}:${t.port}"
        val broken = altSvcLock.withLock { brokenAltSvc.brokenReason(origin, alt) }
        if (broken != null) throw EndpointUnreachable(IllegalStateException("$alt is marked broken"))
        val existing = h3.existing(t)
        val conn =
            existing ?: try {
                h3.connection(t, data, dns).also { it.quic.awaitHandshake() }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (!isTransientRefusal(e)) {
                    val reason = classifyH3Failure(e) ?: FallbackReason.Other
                    altSvcLock.withLock { brokenAltSvc.markBroken(origin, alt, reason) }
                    events.emit("altSvcMarkedBroken") { altSvcMarkedBroken(origin, alt) }
                }
                throw EndpointUnreachable(e)
            }
        if (existing == null) altSvcLock.withLock { recordQuicWorking(network, origin, alt, conn) }
        selected(
            data,
            HttpProtocolVersion.HTTP_3_0,
            if (existing !=
                null
            ) {
                ProtocolReason.ExistingConnection
            } else {
                ProtocolReason.HttpsRecord
            },
            d,
        )
        return try {
            h3.execute(t, data, callContext, extraHeaders, dns, conn)
        } catch (e: H3NotSent) {
            throw EndpointUnreachable(e.cause ?: e)
        }
    }

    /**
     * The ALPN ids this request may use, for the SVCB ALPN sets (RFC 9460 section 7.1.2): a WebSocket's own TCP connection
     * is HTTP/1.1 (it takes HTTP/2 only on a connection that is there already, RFC 8441).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun supportedAlpn(webSocket: Boolean): Set<String> =
        buildSet {
            add("h3")
            add(HTTPS_DEFAULT_ALPN)
            if (config.http2.enabled && !webSocket) add("h2")
        }

    /**
     * SVCB resolution of [url]'s origin and of [altAuthority], waited for while its addresses resolve (into [dns], for the TCP side: section 3,
     * "SVCB-optional clients SHOULD issue in parallel any other DNS queries that might be needed") and at most
     * `httpsRecordExtraWait` longer (section 5.1: an address answer first lets the client connect as if the HTTPS query
     * returned NODATA), all within the connect timeout. A resolution still running goes on, and its records are cached
     * for the next request; this one counts it as [HttpsResolution.None].
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private suspend fun awaitResolutions(
        records: HttpsRecords,
        url: io.ktor.http.Url,
        dns: RequestDns,
        supported: Set<String>,
        // protected answers (section 3.1): wait for the resolution itself, and a timeout is a failure
        secure: Boolean,
        // an Alt-Svc alt-authority to resolve as well (section 9.3)
        altAuthority: Pair<String, Int>?,
    ): Pair<HttpsResolution, HttpsResolution> {
        // section 5: "clients SHOULD issue speculative A and/or AAAA queries in parallel with each SVCB query, based on a
        // predicted value of TargetName": an alias target, looked up into the request's resolution
        val prefetch: (String) -> Unit = { name -> records.background { lookupQuietly(dns, name, url.port) } }
        // the origin's addresses, for the TCP side: in the background, so records that are in do not wait for them
        val addresses = records.background { lookupQuietly(dns, url.host, url.port) }
        val originProgress = AliasProgress()
        val altProgress = AliasProgress()

        // a resolution this request stops waiting for: what it got so far (section 3: the AliasMode endpoint)
        fun cut(progress: AliasProgress): HttpsResolution =
            if (secure) {
                HttpsResolution.Failed(progress.endpoint)
            } else {
                progress.endpoint?.let { HttpsResolution.Endpoints(listOf(it)) }
                    ?: HttpsResolution.None
            }
        return withTimeoutOrNull(config.connectTimeout) {
            coroutineScope {
                val originJob = async { records.resolve(url.host, url.port, supported, originProgress, prefetch) }
                val altJob =
                    altAuthority?.let { (h, p) ->
                        // an alternative on the origin's own name and port is the same service: one resolution
                        if (httpsQueryName(h, p) == httpsQueryName(url.host, url.port)) {
                            originJob
                        } else {
                            async { records.resolve(h, p, supported, altProgress, prefetch) }
                        }
                    }
                val https =
                    launch {
                        originJob.join()
                        altJob?.join()
                    }
                select {
                    https.onJoin {}
                    addresses.onJoin {}
                }
                if (secure) {
                    https.join()
                } else if (!https.isCompleted) {
                    withTimeoutOrNull(config.http3.httpsRecordExtraWait) { https.join() }
                }

                fun outcome(
                    j: kotlinx.coroutines.Deferred<HttpsResolution>,
                    progress: AliasProgress,
                ): HttpsResolution = if (j.isCompleted && !j.isCancelled) j.getCompleted() else cut(progress)
                val result = outcome(originJob, originProgress) to (altJob?.let { outcome(it, altProgress) } ?: HttpsResolution.None)
                originJob.cancel()
                altJob?.cancel()
                result
            }
        } ?: (cut(originProgress) to (if (altAuthority == null) HttpsResolution.None else cut(altProgress)))
    }

    /** [dns]'s answer for [name], within the connect timeout; a failure stays in [dns] for the connection that needs it. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    private suspend fun lookupQuietly(
        dns: RequestDns,
        name: String,
        port: Int,
    ) {
        try {
            withTimeoutOrNull(config.connectTimeout) { dns.lookup(name, port) }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
            // kept in dns: the connection that needs it reports it
        }
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
        tcpDns: RequestDns = dns, // where the fallback over TCP connects
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
            fallbackToH1(target, data, callContext, e, tcpDns, d)
        } catch (
            e: Throwable,
        ) {
            if (data.method.isIdempotent() && (e is QuicException || e is Http3Exception) &&
                data.body.isReplayable()
            ) {
                fallbackToH1(target, data, callContext, e, tcpDns, d)
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
        // a connection the server closed with H3_NO_ERROR after its GOAWAY ended in order (RFC 9114 section 5.2): the alternative works
        if (marksAlternativeBroken(h3Failure) && !data.attributes.contains(H3ClosedAfterGoAwayKey)) {
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
 * accept queue, `Drain`, a stop; also quic-go's `sendConnectionRefused` and quinn's `refuse`), at the client's first
 * Initial or on an established connection (a Kuicksilver server whose handshake completed into a full accept queue
 * closes it so, "accept queue full"; quic-go's `handleNewConn` too). That says nothing against
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

/** No connection to an endpoint of the HTTPS records could be set up, before the request went out: try the next one. */
internal class EndpointUnreachable(
    cause: Throwable,
) : Exception(cause.message, cause)

/** The shortest `httpsRecordExtraWait` allowed (RFC 9460 section 5.1). */
internal val MIN_HTTPS_RECORD_EXTRA_WAIT = kotlin.time.Duration.parse("50ms")

/** The longest `httpsRecordExtraWait` allowed. */
internal val MAX_HTTPS_RECORD_EXTRA_WAIT = 1.seconds

/** The longest an HTTPS record lookup runs, whatever the connect timeout. */
internal val MAX_HTTPS_RECORD_QUERY = 30.seconds

/**
 * How long after the engine's creation requests wait for the first value of the networks `connectionMigration` follows
 * (the system answers at once: Android's default-network callback when a network is up, Apple's path monitor); past it
 * they go on without a known network and without waiting.
 */
internal val FIRST_NETWORK_WAIT = kotlin.time.Duration.parse("200ms")

/** Whether [host] (a URL host) is an IP address, which has no HTTPS records: an IPv6 literal or a dotted IPv4 address. */
internal fun isIpLiteral(host: String): Boolean =
    ':' in host || host.startsWith('[') ||
        (host.split('.').let { p -> p.size == 4 && p.all { it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) } })

/** RFC 9110 section 9.2.2. */
internal fun HttpMethod.isIdempotent(): Boolean =
    this in setOf(HttpMethod.Get, HttpMethod.Head, HttpMethod.Options, HttpMethod.Put, HttpMethod.Delete, HttpMethod("TRACE"))
