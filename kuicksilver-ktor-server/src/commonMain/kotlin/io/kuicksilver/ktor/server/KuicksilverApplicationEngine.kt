// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.events.Events
import io.ktor.events.raiseCatching
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationEnvironment
import io.ktor.server.application.ApplicationStopPreparing
import io.ktor.server.application.ServerReady
import io.ktor.server.engine.ApplicationEngine
import io.ktor.server.engine.BaseApplicationEngine
import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorConfig
import io.ktor.server.engine.withPort
import io.ktor.utils.io.ByteReadChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.SecuritySensitive
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.ktor.network.ipv6Bindable
import io.kuicksilver.ktor.server.h1.installH1CallHandling
import io.kuicksilver.native.LeakRegistry
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The Kuicksilver server engine (docs/guide/ktor.md): HTTP/1.1 over TLS on TCP through the CIO connection pipeline of Ktor
 * (HTTP/2 there too with `http2 { enabled }`), and HTTP/3 on UDP on the same port. Start it with `embeddedServer(Kuicksilver, ...)`.
 */
public class KuicksilverApplicationEngine(
    environment: ApplicationEnvironment,
    monitor: Events,
    developmentMode: Boolean,
    /** The engine settings and connectors this engine was created with; read when it starts. */
    public val configuration: Configuration,
    internal val applicationProvider: () -> Application,
) : BaseApplicationEngine(environment, monitor, developmentMode) {
    /**
     * The engine's configuration (docs/guide/configuration.md, "Ktor server"): [requestHeaderTimeout] at the top, everything
     * else in blocks — [tls], connectors ([tlsConnector], [plainConnector], Ktor's own), [http1], [http2], [http3],
     * [webSockets], [tcp], [observability]. Ktor's own `connectors`, `shutdownGracePeriod`, `shutdownTimeout` and the group
     * sizes are inherited.
     */
    public class Configuration : BaseApplicationEngine.Configuration() {
        /**
         * The time a client has to send a complete request head, on every protocol: over HTTP/1.1 the request line and header
         * fields, counted from the accepted TCP connection for the first request (the TLS handshake included) and from the end
         * of the previous response for the next one on a keep-alive connection; bytes that trickle in do not extend it. A
         * client that sent part of a head by then gets `408 Request Timeout` and the connection closes; one that sent nothing
         * is closed without a response. It also bounds the field-block deadline `maxHeaderBlockTime` of `http2 { settings { } }`
         * and `http3 { settings { } }`, and the PROXY protocol header's wait (a connector with `proxyProtocol { }` needs at
         * least 3 s: the start fails below). 30 s by default.
         *
         * @throws IllegalArgumentException when set to zero, a negative duration or [Duration.INFINITE].
         */
        @SecuritySensitive
        public var requestHeaderTimeout: Duration = 30.seconds
            set(value) {
                require(value.isPositive() && value.isFinite()) { "requestHeaderTimeout must be a positive, finite duration" }
                field = value
            }

        /** The TLS of every TLS connector and of Ktor's own connectors once it has an identity; change it with [tls]. */
        public val tls: ServerTlsConfig = ServerTlsConfig()

        /** Configures [tls] in place: `tls { pemFiles("/etc/…/fullchain.pem", "/etc/…/privkey.pem") }`. */
        public fun tls(block: ServerTlsConfig.() -> Unit) {
            tls.block()
        }

        /** HTTP/1.1; change it with [http1]. */
        public val http1: Http1ServerConfig = Http1ServerConfig()

        /** Configures [http1] in place. */
        public fun http1(block: Http1ServerConfig.() -> Unit) {
            http1.block()
        }

        /** HTTP/2 on the TLS connectors; change it with [http2]. */
        public val http2: Http2ServerConfig = Http2ServerConfig()

        /** Configures [http2] in place: `http2 { enabled = false }`. */
        public fun http2(block: Http2ServerConfig.() -> Unit) {
            http2.block()
        }

        /** HTTP/3 on the UDP twin of every TLS connector's port; change it with [http3]. */
        public val http3: Http3ServerConfig = Http3ServerConfig()

        /** Configures [http3] in place: `http3 { endpoint { maxConnectionsPerIp = null } }`. */
        public fun http3(block: Http3ServerConfig.() -> Unit) {
            http3.block()
        }

        /** WebSockets over every protocol; change it with [webSockets]. */
        public val webSockets: ServerWebSocketsConfig = ServerWebSocketsConfig()

        /** Configures [webSockets] in place. */
        public fun webSockets(block: ServerWebSocketsConfig.() -> Unit) {
            webSockets.block()
        }

        /** The TCP connections' idle timeout and limits; change it with [tcp]. */
        public val tcp: TcpLimitsConfig = TcpLimitsConfig()

        /**
         * Configures [tcp] in place: `tcp { idleTimeout = 2.minutes }`, or `tcp { maxConnectionsPerIp = 256 }` for a server that
         * faces its clients directly.
         */
        public fun tcp(block: TcpLimitsConfig.() -> Unit) {
            tcp.block()
        }

        /** Logs, traces and events; change it with [observability]. */
        public val observability: ServerObservability = ServerObservability()

        /** Configures [observability] in place. */
        public fun observability(block: ServerObservability.() -> Unit) {
            observability.block()
        }

        /**
         * Adds a TLS connector: HTTP/1.1 (and HTTP/2) over TLS on TCP plus HTTP/3 on UDP on the same port, served with the
         * engine's [tls] and the connector's own `tls { }` on top: `tlsConnector { port = 443 }`.
         *
         * @throws IllegalArgumentException for a port outside 0..65535, or an invalid `proxyProtocol { }`.
         */
        public fun tlsConnector(block: KuicksilverTlsConnector.Builder.() -> Unit) {
            connectors.add(KuicksilverTlsConnector.Builder().apply(block).build())
        }

        /**
         * Adds a plain HTTP/1.1 connector, as Ktor's `connector { }`, with the PROXY protocol, `allowMisdirectedHosts` and
         * cleartext HTTP/2 ([KuicksilverPlainConnector.Builder.h2c]) as options. Served with TLS when [tls] has an identity.
         *
         * @throws IllegalArgumentException for a port outside 0..65535, or an invalid `proxyProtocol { }`.
         */
        public fun plainConnector(block: KuicksilverPlainConnector.Builder.() -> Unit = {}) {
            connectors.add(KuicksilverPlainConnector.Builder().apply(block).build())
        }

        /** Set by `EngineMain` (`kuicksilver.connector.allowMisdirectedHosts`): the deployment port takes every host. */
        internal var deploymentAllowMisdirectedHosts: Boolean = false

        /** Set by `EngineMain` (`kuicksilver.connector.proxyProtocol.*`): the PROXY protocol on the deployment port; null for none. */
        internal var deploymentProxyProtocol: ProxyProtocolConfig? = null

        /** Set by `EngineMain` (`kuicksilver.connector.h2c`): cleartext HTTP/2 on the plain deployment port (a Ktor `connector`). */
        @OptIn(ExperimentalKuicksilverApi::class)
        internal var deploymentH2c: H2cMode = H2cMode.Off

        /**
         * Set by `EngineMain` when `ktor.deployment.host` (or `-host`) is not given: its deployment connectors bind every
         * interface as a host-less connector of ours does (`::`, or `0.0.0.0` without IPv6), not Ktor's `0.0.0.0`.
         */
        internal var deploymentEveryInterface: Boolean = false

        /** Tests: whether this host can bind IPv6 (false: the IPv4-only fallback of a host-less connector); null asks the system. */
        internal var ipv6BindableForTest: Boolean? = null

        /** Tests shorten the HTTP/1.1 send-stall deadline with this; null keeps the engine's own. */
        internal var sendStallTimeoutForTest: Duration? = null

        /**
         * Test hook: a bound on the whole close of an accepted TLS socket (`setCloseTimeout`), which also stretches its wait
         * for the client's close_notify from 3 s to this bound (a test then tells "the FIN went out at once" from "after
         * that wait" by a wide margin); null keeps the engine's own (no bound of the socket's).
         */
        internal var tlsCloseTimeoutForTest: Duration? = null

        /** Tests drive the HTTP/2 connections' clock (monotonic nanoseconds: reset budgets, protocol deadlines) with this. */
        internal var h2ClockForTest: (() -> Long)? = null

        /** Test hook: runs once an HTTP/2 connection's client preface was read, still inside its deadline. */
        internal var h2PrefaceForTest: (suspend () -> Unit)? = null

        /**
         * Test hook: runs inside the wait for the client preface that races the stop, before the preface is awaited (a
         * test that never returns from it leaves the stop as the only side that can win).
         */
        internal var h2PrefaceAwaitForTest: (suspend () -> Unit)? = null

        /**
         * Test hook: runs inside an h2c connector's check for the client preface ([H2cMode.WithHttp11]) that races the
         * stop, with the connection's input and the listener's draining job, before the check looks at it (a test that
         * never returns from it leaves the stop as the only side that can win).
         */
        internal var h2cPrefaceCheckForTest: (suspend (ByteReadChannel, Job) -> Unit)? = null

        /**
         * Test hook: runs before an HTTP/2 connection's wait for the client preface races the stop, with the connection and
         * the listener's draining job (a test holds it here until the core took a request and the stop began).
         */
        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
        internal var h2BeforePrefaceRaceForTest: (
            suspend (io.kuicksilver.http2.runtime.H2ServerConnection, kotlinx.coroutines.Job) -> Unit
        )? =
            null

        /**
         * Tests run each HTTP/2 request stream's release at the end of its handling through this, with the handler's
         * cancellation in flight (null for none); null releases it.
         */
        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
        internal var h2ReleaseForTest: ((io.kuicksilver.http2.runtime.H2ServerStream, CancellationException?) -> Unit)? = null

        /** How the HTTP/3 listener binds (tests replace it to simulate platforms without a QUIC server). */
        internal var http3Bind: suspend (
            InetSocketAddress,
            QuicEndpointConfig,
            Http3Settings,
        ) -> Http3Endpoint = { a, c, s -> Http3Endpoint.bind(a, c, s) }

        /**
         * The QUIC settings of the HTTP/3 listeners: the `http3 { quic { } }` block, its derived options refused, with
         * `resetStreamAt` on for WebTransport (its streams keep their header when reset, draft-ietf-webtrans-http3-17
         * section 4.4) and the stream limits a default that fits the WebTransport sessions ([quicStreamLimits]). Throws
         * IllegalArgumentException naming a derived option that was assigned, or a stream limit that is too small.
         */
        @OptIn(ExperimentalKuicksilverApi::class)
        internal fun resolveQuic(): QuicConfig {
            val q = http3.quicBuilder
            val assigned = q.assignedOptions()
            refuseDerived("http3 { quic { ", assigned, QUIC_DERIVED)
            val wt = http3.webTransport
            val sessions = if (wt.enabled) wt.maxSessionsPerConnection.toLong() else 0L
            val built = q.build()
            requireUniStreamCredit(built)
            val (bidi, uni) =
                quicStreamLimits(
                    built,
                    assigned,
                    sessions,
                    wt.initialMaxStreamsBidi,
                    wt.initialMaxStreamsUni,
                    wt.initialMaxStreamsBidi != 0L || wt.initialMaxStreamsUni != 0L || wt.initialMaxData != 0L,
                )
            val resetStreamAt = wt.enabled && !built.resetStreamAt
            if (bidi == built.maxBidiStreams && uni == built.maxUniStreams && !resetStreamAt) return built
            return built
                .toBuilder()
                .apply {
                    maxBidiStreams = bidi
                    expert {
                        maxUniStreams = uni
                        if (resetStreamAt) this.resetStreamAt = true
                    }
                }.build()
        }

        /**
         * The HTTP/3 SETTINGS of the listeners: the `http3 { settings { } }` block, its derived options refused, with
         * `maxHeaderBlockTime` bounded by [requestHeaderTimeout], Extended CONNECT (RFC 9220) on for WebSockets,
         * WebTransport and CONNECT-UDP, WebTransport's SETTINGS from `http3 { webTransport { } }` and the early-data policy
         * from `http3 { earlyData { policy } }`.
         */
        @OptIn(ExperimentalKuicksilverApi::class)
        internal fun resolveHttp3Settings(): Http3Settings {
            refuseDerived("http3 { settings { ", http3.settingsBuilder.assignedOptions(), H3_DERIVED)
            val wt = http3.webTransport
            val connect = webSockets.overHttp3 || wt.enabled || http3.connectUdp
            val b = http3.settingsBuilder.build().toBuilder()
            if (connect) b.enableConnectProtocol = true
            b.earlyData = http3.earlyData.policy
            if (wt.enabled) {
                b.webTransport {
                    enabled = true
                    maxSessions = wt.maxSessionsPerConnection
                    initialMaxStreamsBidi = wt.initialMaxStreamsBidi
                    initialMaxStreamsUni = wt.initialMaxStreamsUni
                    initialMaxData = wt.initialMaxData
                }
            }
            return h3SettingsWithin(b.build(), requestHeaderTimeout)
        }

        /** The HTTP/2 settings of every HTTP/2 connection, `maxHeaderBlockTime` bounded by [requestHeaderTimeout]. */
        @OptIn(ExperimentalKuicksilverApi::class)
        internal fun resolveHttp2Settings(): io.kuicksilver.http2.Http2Settings =
            h2SettingsWithin(http2.settingsBuilder.build(), requestHeaderTimeout)

        /**
         * The endpoint settings of every HTTP/3 listener beyond the server and admission the engine adds: the
         * `http3 { endpoint { } }` block, its connection ID length `expert { connectionIdLength }`, or the load balancer's.
         * Throws IllegalArgumentException for an explicit length next to a load balancer, which dictates it.
         */
        @OptIn(ExperimentalKuicksilverApi::class)
        internal fun endpointBase(): QuicEndpointConfig.Builder {
            refuseDerivedEndpoint()
            val e = http3.endpoint
            val lb = e.loadBalancer
            return e.endpointBuilder.also {
                it.loops = e.loops
                it.maxConnections = e.maxConnections
                it.maxConnectionsPerIp = e.maxConnectionsPerIp
                it.acceptQueue = e.acceptQueue
                it.maxConnectionLifetime = e.maxConnectionLifetime
                it.loadBalancer = e.loadBalancer
                it.connectionIdLength = lb?.connectionIdLength ?: e.expert.connectionIdLength
            }
        }

        /** Refuses `http3 { endpoint { expert { connectionIdLength } } }` next to a load balancer, which dictates the length. */
        @OptIn(ExperimentalKuicksilverApi::class)
        internal fun refuseDerivedEndpoint() {
            val e = http3.endpoint
            val lb = e.loadBalancer ?: return
            require(!e.expert.connectionIdLengthAssigned) {
                "http3 { endpoint { expert { connectionIdLength } } } is derived by the engine (the loadBalancer's QUIC-LB " +
                    "configuration dictates it: ${lb.connectionIdLength} bytes); remove it"
            }
        }

        internal companion object {
            /**
             * RFC 9114 section 6.2: "These transport parameters SHOULD also provide at least 1,024 bytes of flow-control
             * credit to each unidirectional stream" (`initial_max_stream_data_uni`, the QuicConfig's initial stream window).
             */
            @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
            fun requireUniStreamCredit(q: QuicConfig) {
                require(q.initialStreamWindow >= 1024) {
                    "http3 { quic { flowControl { initialStreamWindow } } } must be at least 1024 (RFC 9114 section 6.2: at least " +
                        "1,024 bytes of flow-control credit SHOULD go to each unidirectional stream), not ${q.initialStreamWindow}"
                }
            }

            /** The QUIC options the server engine derives, and why (the refusal names both). */
            val QUIC_DERIVED: Map<String, String> =
                mapOf(
                    "expert.resetStreamAt" to "on with http3 { webTransport { enabled } }, draft-ietf-webtrans-http3-17 section 4.4",
                    "expert.cancelErrorCode" to "HTTP/3 resets with its own codes (RFC 9114 section 8.1)",
                )

            /** The HTTP/3 SETTINGS the server engine derives. */
            val H3_DERIVED: Map<String, String> =
                mapOf(
                    "enableConnectProtocol" to "on for WebSockets, WebTransport and CONNECT-UDP (RFC 9220)",
                    "h3Datagram" to "follows the QUIC datagrams (RFC 9297)",
                    "webTransport" to "enabled and maxSessions are http3 { webTransport { enabled; maxSessionsPerConnection } }",
                    "webTransport.limits" to
                        "initialMaxStreamsBidi, initialMaxStreamsUni and initialMaxData are http3 { webTransport { } }",
                    "earlyData" to "set with http3 { earlyData { policy } }",
                )

            /**
             * The stream limits of the HTTP/3 connections, bidirectional and unidirectional. An explicit value is kept (the
             * bidirectional one at least 100, RFC 9114 section 6.1: "at least 100 request streams SHOULD be permitted at a
             * time"; the unidirectional one at least 3, section 6.2: the peer opens its control and QPACK streams); one left
             * alone is the default raised so that [sessions] WebTransport sessions at their initial limits fit
             * (draft-ietf-webtrans-http3-17 section 5.1): `max(100, sessions x (bidi + 1))` bidirectional streams (each
             * session's streams and its CONNECT stream) and `max(100, 3 + sessions x uni)` unidirectional ones. With
             * WebTransport flow control ([flowControl]) an explicit value they do not fit in is refused here, naming the
             * options, rather than at bind. The options are those of `http3 { quic { } }` and `http3 { webTransport { } }`.
             */
            fun quicStreamLimits(
                built: QuicConfig,
                assigned: Set<String>,
                sessions: Long,
                bidiPerSession: Long,
                uniPerSession: Long,
                flowControl: Boolean,
            ): Pair<Long, Long> {
                val needBidi = if (flowControl) atLeast(sessions, bidiPerSession + 1, 0) else 0
                val needUni = if (flowControl) atLeast(sessions, uniPerSession, 3) else 3
                val sessionsOption = "http3 { webTransport { maxSessionsPerConnection } } ($sessions)"
                val uni =
                    if ("expert.maxUniStreams" in assigned) {
                        val n = built.maxUniStreams
                        require(n >= 3) {
                            "http3 { quic { expert { maxUniStreams } } } must be at least 3 (RFC 9114 section 6.2: the peer " +
                                "opens its control and QPACK streams), not $n"
                        }
                        require(n >= needUni) {
                            "http3 { quic { expert { maxUniStreams } } } ($n) is below 3 + $sessionsOption x " +
                                "initialMaxStreamsUni ($uniPerSession): raise it, or leave it to the engine"
                        }
                        n
                    } else {
                        maxOf(built.maxUniStreams, needUni)
                    }
                val bidi =
                    if ("maxBidiStreams" in assigned) {
                        val n = built.maxBidiStreams
                        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                        require(n >= 100 || Http3Endpoint.allowFewerBidiStreamsForTest) {
                            "http3 { quic { maxBidiStreams } } must be at least 100 (RFC 9114 section 6.1: at least 100 request " +
                                "streams SHOULD be permitted at a time), not $n"
                        }
                        require(n >= needBidi) {
                            "http3 { quic { maxBidiStreams } } ($n) is below $sessionsOption x (initialMaxStreamsBidi " +
                                "($bidiPerSession) + its CONNECT stream): raise it, or leave it to the engine"
                        }
                        n
                    } else {
                        maxOf(built.maxBidiStreams, needBidi)
                    }
                return bidi to uni
            }

            /** `extra + sessions x perSession`, at most 2^60 (the most streams QUIC can grant, RFC 9000 section 4.6). */
            private fun atLeast(
                sessions: Long,
                perSession: Long,
                extra: Long,
            ): Long {
                val max = 1L shl 60
                if (sessions == 0L) return extra
                if (perSession > (max - extra) / sessions) return max
                return extra + sessions * perSession
            }

            /** Refuses the derived options a block assigned, naming the first one and its source. */
            fun refuseDerived(
                prefix: String,
                assigned: Set<String>,
                derived: Map<String, String>,
            ) {
                val first = derived.keys.firstOrNull { it in assigned } ?: return
                val parts = first.split('.')
                val path = parts.dropLast(1).joinToString("") { "$it { " } + parts.last() + " }".repeat(parts.size - 1)
                throw IllegalArgumentException("$prefix$path } } is derived by the engine (${derived.getValue(first)}); remove it")
            }
        }
    }

    /**
     * Where the engine's own lines go: `observability { logger }`, Ktor's `environment.log` when that is
     * [ServerObservability.ApplicationLog] (the default).
     */
    internal val log: io.ktor.util.logging.Logger =
        configuration.observability.logger.let {
            if (it === ServerObservability.ApplicationLog) environment.log else KuicksilverLoggerAsKtor(it)
        }

    /** The configuration's [KuicksilverServerEventListener], behind a guard that logs its failures. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    internal val events = ServerEvents(configuration.observability.eventListener, log)

    /** The engine's `tls { }` as served, resolved when the engine starts ([ResolvedServerTls.None] before). */
    @Volatile
    internal var engineTls: ResolvedServerTls = ResolvedServerTls.None
        private set

    /** Every TLS the engine resolved at its start (the engine's first, then each connector's own): watched files, closed identities. */
    private val resolvedTls = ArrayList<ResolvedServerTls>()

    /** The QUIC settings of the HTTP/3 listeners ([Configuration.resolveQuic]), resolved when the engine starts. */
    internal var h3Quic: QuicConfig = QuicConfig.Default
        private set

    /** The HTTP/3 SETTINGS of the listeners ([Configuration.resolveHttp3Settings]), resolved when the engine starts. */
    internal var h3Settings: Http3Settings = Http3Settings.Default
        private set

    /** The HTTP/2 settings of every HTTP/2 connection ([Configuration.resolveHttp2Settings]), resolved when the engine starts. */
    internal var h2Settings: io.kuicksilver.http2.Http2Settings = io.kuicksilver.http2.Http2Settings.Default
        private set

    /** Where the HTTP/3 endpoints log: `observability { logger }`, the application's log by default. */
    internal val quicLogger: KuicksilverLogger
        get() =
            configuration.observability.logger.let {
                if (it === ServerObservability.ApplicationLog) KtorLogBridge(environment.log) else it
            }

    /** The value of [http3Advertising], read by every HTTP/1.1 response head, the HTTP/3 accept loops and QUIC admission. */
    @Volatile
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    internal var advertising: Http3Advertising = Http3Advertising.On
        private set

    /**
     * Whether HTTP/3 is advertised and new HTTP/3 connections accepted, switched at runtime (docs/guide/ktor.md, "Turning HTTP/3
     * off on the server"); [Http3Advertising.On] until set. Every response reads it as its head goes out (so the next
     * response on a keep-alive connection already follows a change), and every new client Initial when the QUIC endpoint
     * admits it. Setting [Http3Advertising.Drain] sends GOAWAY to every live HTTP/3 connection in the background and returns
     * at once; a connection accepted while it is set gets GOAWAY too. GOAWAY cannot be taken back: going back to
     * [Http3Advertising.On] or [Http3Advertising.Clear] lets new connections in, while the drained ones finish their requests
     * and close. Safe to set from any thread, before or after the start.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var http3Advertising: Http3Advertising
        get() = advertising
        set(value) {
            advertising = value
            // after the write: a connection registered after this round took its list reads Drain in its accept loop
            if (value == Http3Advertising.Drain) lastDrainRound = serverScope?.launch { goAwayAll() }
        }

    /**
     * GOAWAY to every live HTTP/3 connection (RFC 9114 section 5.2), all at once as at a stop: each waits about two round trips
     * between its two frames. Waits for the start first, so the listeners are all there; one that started meanwhile checks
     * the switch for each connection it accepts.
     */
    private suspend fun goAwayAll() {
        startupJob.join()
        // switched back while the start was still running: no GOAWAY for a mode that is no longer in force
        if (advertising != Http3Advertising.Drain) return
        coroutineScope {
            for (l in h3ListenersForProbe) for (c in l.live()) launch { runCatching { c.goAway() } }
        }
    }

    /**
     * Moves every HTTP/3 listener to another QUIC-LB configuration (`http3 { endpoint { loadBalancer } }` must have been
     * set). Waits for the start first, so every listener is there; checks [config] against every listener before it
     * changes any, so a refused configuration leaves them all as they were.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public suspend fun updateLoadBalancer(config: io.kuicksilver.quic.QuicLbConfig?) {
        check(configuration.http3.endpoint.loadBalancer != null) {
            "updateLoadBalancer needs http3 { endpoint { loadBalancer } } in the engine configuration"
        }
        startupJob.join()
        val endpoints = h3Endpoints.toList()
        for (e in endpoints) e.checkLoadBalancer(config)
        for (e in endpoints) e.updateLoadBalancer(config)
    }

    /**
     * The statistics of every HTTP/3 listener's QUIC endpoint (`Http3Endpoint.stats`: datagrams, drops, admission and limit
     * refusals, handshakes; docs/guide/quic.md, "Observability"), one per TLS connector serving HTTP/3, in the order of
     * the connectors. Empty before the start completes and when no connector serves HTTP/3; after a stop the endpoints'
     * final counts. Each read takes a new snapshot; safe from any thread.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public val http3Stats: List<io.kuicksilver.quic.EndpointStats>
        get() = startedH3Endpoints.map { it.stats }

    /**
     * Per TLS connector, in the order the connectors started: whether it serves HTTP/3 and why not ([Http3Status]), for
     * example its UDP socket cannot set Don't Fragment (`QuicException.DontFragmentUnavailable`, no QUIC without DF: RFC 9000
     * section 14), or only for one address family. Empty before the start completes. Safe from any thread.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public val http3Status: List<Http3Status>
        get() = h3StatusList

    /** [http3Status] as the start records it (a new list per change). */
    @Volatile
    internal var h3StatusList: List<Http3Status> = emptyList()

    /** [h3Endpoints] as published once the start completed (empty before): what [http3Stats] reads from other threads. */
    @Volatile
    private var startedH3Endpoints: List<Http3Endpoint> = emptyList()

    /** The server job's scope while it runs (null before the start): where [http3Advertising] sends its GOAWAY round. */
    @Volatile
    private var serverScope: CoroutineScope? = null

    /** The background GOAWAY round of the last switch to [Http3Advertising.Drain] (tests join it); null before one. */
    @Volatile
    internal var lastDrainRound: Job? = null

    /** The grace period of the stop in progress: each HTTP/3 endpoint gets it for `QuicEndpoint.shutdown`. */
    @Volatile
    private var stopGraceMillis = 0L

    /**
     * How long an HTTP/3 connection that is idle after the stop's final GOAWAY waits for its client to close it before the
     * server closes it: a quarter of the grace period, at most the three seconds of `Http3Connection.goAway`. A browser or
     * curl keeps its idle connection open, and with the full three seconds a stop whose grace period was shorter (Ktor's
     * `stop(500, 500)`) could never end gracefully: it always ran out its grace and cut what was left. The other three
     * quarters leave room for the GOAWAY round before it (2 RTT, at least 50 ms) and the QUIC closing period after it.
     */
    internal val stopCloseFallback: Duration get() = (stopGraceMillis / 4).coerceAtLeast(0).milliseconds

    /** Test hook: the idle-close fallback each HTTP/3 connection gets with the stop's GOAWAY ([stopCloseFallback]). */
    @Volatile
    internal var stopGoAwayFallbackForTest: ((Duration) -> Unit)? = null

    /** The stop's GOAWAY to [c], with [stopCloseFallback] for an idle client. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal suspend fun stopGoAway(c: io.kuicksilver.http3.Http3Connection) {
        val fallback = stopCloseFallback
        stopGoAwayFallbackForTest?.invoke(fallback)
        c.goAway(fallback)
    }

    /** Whether the last stop ran out its grace period and cancelled what was left (tests). */
    @Volatile
    internal var stopWasForcedForTest = false

    internal val engineDispatcher = Dispatchers.IO
    internal val userDispatcher = Dispatchers.IO
    private val startupJob: CompletableDeferred<Unit> = CompletableDeferred()
    private val stopRequest: CompletableJob = Job()

    @Volatile
    private var serverJob: Job = Job()

    init {
        // HTTP/1.1 calls: a body timeout answered 408, an unread body left to the connection (h1/H1CallPhase.kt)
        pipeline.installH1CallHandling()
        serverJob = initServerJob()
        serverJob.invokeOnCompletion { cause ->
            cause?.let { stopRequest.completeExceptionally(cause) }
            cause?.let { startupJob.completeExceptionally(cause) }
        }
    }

    /** Starts the server and suspends until it listens; with [wait] true it also suspends until it stops. */
    override suspend fun startSuspend(wait: Boolean): ApplicationEngine {
        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)
        io.kuicksilver.ktor.network.KtorVersionPolicy
            .check(*KTOR_ARTIFACTS.toTypedArray()) // docs/guide/ktor.md, "Supported Ktor versions"
        serverJob.start()
        startupJob.await()
        monitor.raiseCatching(ServerReady, environment, environment.log) // the application's subscribers
        if (wait) serverJob.join()
        return this
    }

    /** Starts the server and blocks until it listens; with [wait] true it also blocks until it stops. */
    override fun start(wait: Boolean): ApplicationEngine = runBlocking { startSuspend(wait) }

    /** Stops the server: running requests get [gracePeriodMillis] to finish, and are cancelled after that; the whole stop gets [timeoutMillis]. */
    override suspend fun stopSuspend(
        gracePeriodMillis: Long,
        timeoutMillis: Long,
    ) {
        stopGraceMillis = gracePeriodMillis
        stopRequest.complete()
        try {
            val result =
                withTimeoutOrNull(gracePeriodMillis) {
                    serverJob.join()
                    true
                }
            stopWasForcedForTest = result == null
            if (result == null) {
                serverJob.cancel()
                withTimeoutOrNull(timeoutMillis - gracePeriodMillis) { serverJob.join() }
            }
        } finally {
            // the ECH keys EngineMain read (`kuicksilver.tls.echKeys`) are the engine's own: their native set is freed with it
            @OptIn(ExperimentalKuicksilverApi::class)
            if (configuration.tls.closeEchKeysOnStop) configuration.tls.echKeys?.close()
        }
    }

    /** Stops the server like [stopSuspend], blocking the calling thread. */
    override fun stop(
        gracePeriodMillis: Long,
        timeoutMillis: Long,
    ): Unit = runBlocking { stopSuspend(gracePeriodMillis, timeoutMillis) }

    /** A connector as the engine runs it: TLS (with its connector) or plain HTTP. */
    internal class Listener(
        val config: EngineConnectorConfig,
        val tls: KuicksilverTlsConnector?,
        /** `EngineMain`'s `kuicksilver.connector.allowMisdirectedHosts` for the plain deployment port (a Ktor connector). */
        gateway: Boolean = false,
        /** `EngineMain`'s `kuicksilver.connector.proxyProtocol.*` for the plain deployment port. */
        deploymentProxy: ProxyProtocolConfig? = null,
        /** `EngineMain`'s `kuicksilver.connector.h2c` for the plain deployment port (a Ktor connector, not a plain one of ours). */
        @OptIn(ExperimentalKuicksilverApi::class)
        deploymentH2c: H2cMode = H2cMode.Off,
    ) {
        /** Every client is a trusted gateway: no request is rejected as misdirected (RFC 9110 section 7.4). */
        val trustedGateway: Boolean =
            tls?.allowMisdirectedHosts ?: (((config as? KuicksilverPlainConnector)?.allowMisdirectedHosts ?: false) || gateway)

        /** The PROXY protocol of the connector's TCP side, or null. */
        val proxyProtocol: ProxyProtocolConfig? =
            tls?.proxyProtocol ?: (config as? KuicksilverPlainConnector)?.proxyProtocol ?: deploymentProxy

        /** Cleartext HTTP/2 on this connector (RFC 9113 section 3.3); always [H2cMode.Off] on a TLS one. */
        @OptIn(ExperimentalKuicksilverApi::class)
        val h2c: H2cMode = if (tls != null) H2cMode.Off else (config as? KuicksilverPlainConnector)?.h2c ?: deploymentH2c
    }

    /**
     * A connector of ours without a host binds `::`, one dual-stack socket per protocol; on a host without IPv6 (a kernel
     * with it disabled, a JVM with `java.net.preferIPv4Stack`) it binds `0.0.0.0` instead, and says so at Info. So do the
     * deployment connectors of `EngineMain` when `ktor.deployment.host` is not set ([Configuration.deploymentEveryInterface]):
     * the cleartext port here, Ktor's `-sslPort` connector in [resolve].
     */
    private fun everyInterfaceOf(c: EngineConnectorConfig): EngineConnectorConfig {
        val ours = (c as? KuicksilverTlsConnector)?.everyInterface ?: (c as? KuicksilverPlainConnector)?.everyInterface
        val deployment = ours == null && configuration.deploymentEveryInterface
        if (ours != true && !deployment) return c
        val host = everyInterfaceHost(c)
        return when (c) {
            is KuicksilverTlsConnector -> {
                if (host == c.host) c else c.withHost(host)
            }

            is KuicksilverPlainConnector -> {
                if (host == c.host) c else c.withHost(host)
            }

            else -> {
                if (c.type == ConnectorType.HTTP) {
                    io.ktor.server.engine.EngineConnectorBuilder(ConnectorType.HTTP).also {
                        it.host = host
                        it.port = c.port
                    }
                } else {
                    c // Ktor's sslConnector: its host is set where it becomes ours ([resolve])
                }
            }
        }
    }

    /** `::`, or `0.0.0.0` (said at Info for [c]) where this host cannot bind IPv6. */
    private fun everyInterfaceHost(c: EngineConnectorConfig): String {
        if (configuration.ipv6BindableForTest ?: ipv6Bindable()) return EVERY_INTERFACE
        log.info("$c: no IPv6 on this host, so every interface is every IPv4 one (0.0.0.0)")
        return IPV4_EVERY_INTERFACE
    }

    private fun resolve(c: EngineConnectorConfig): Listener =
        when {
            c is KuicksilverTlsConnector -> {
                val r = c.resolved(engineTls)
                if (r.tls !== engineTls) resolvedTls += r.tls
                Listener(r, r)
            }

            c.type == ConnectorType.HTTP -> {
                // RFC 9113 section 3.3: "HTTP/2 connections over TLS MUST use protocol negotiation in TLS"; a plain connector
                // the identity turns into a TLS one cannot keep its h2c, and dropping it silently would hide the mistake
                @OptIn(ExperimentalKuicksilverApi::class)
                val h2c = (c as? KuicksilverPlainConnector)?.h2c ?: configuration.deploymentH2c
                val identity = engineTls.identity
                @OptIn(ExperimentalKuicksilverApi::class)
                require(identity == null || h2c == H2cMode.Off) {
                    "h2c ($h2c) needs a plain connector, but $c serves TLS with the identity of tls { }: drop the identity " +
                        "(kuicksilver.tls.*) for that port, or serve HTTP/2 there over TLS (on by default)"
                }
                if (identity != null) {
                    val plain = c as? KuicksilverPlainConnector
                    // a plain connector served with the engine's identity keeps its PROXY protocol and its gateway exemption
                    val tls =
                        KuicksilverTlsConnector(
                            c.host,
                            c.port,
                            emptyList(),
                            plain?.proxyProtocol ?: configuration.deploymentProxyProtocol,
                            (plain?.allowMisdirectedHosts ?: false) || configuration.deploymentAllowMisdirectedHosts,
                            null,
                        ).resolved(engineTls)
                    Listener(tls, tls)
                } else {
                    Listener(
                        c,
                        null,
                        configuration.deploymentAllowMisdirectedHosts,
                        deploymentProxy = configuration.deploymentProxyProtocol,
                        deploymentH2c = configuration.deploymentH2c,
                    )
                }
            }

            else -> {
                // Ktor's sslConnector (JVM `-sslPort`, `ktor.security.ssl.*`) has its own key store, trust store and protocols:
                // the settings of tls { } it cannot express would silently not apply to it, so the combination is refused
                val t = configuration.tls
                if (t.clientTrust != null || t.clientAuth != ClientAuth.None) {
                    throw TlsException.Config(
                        "tls { clientAuth } and tls { clientTrust } (kuicksilver.tls.clientAuth, kuicksilver.tls.clientCa) do not " +
                            "apply to $c: use ktor.security.ssl.trustStore there, or serve the port with tls { } (kuicksilver.tls.*)",
                    )
                }
                // the same for the TLS versions: Ktor's own key for that connector is ktor.security.ssl.enabledProtocols
                if (t.versions != TlsVersions.Tls13) {
                    throw TlsException.Config(
                        "tls { versions } (kuicksilver.tls.versions) does not apply to $c: use ktor.security.ssl.enabledProtocols there",
                    )
                }
                // and the key-exchange groups and ECH keys, which Ktor's sslConnector has no setting for
                @OptIn(ExperimentalKuicksilverApi::class)
                if (t.echKeys != null) {
                    throw TlsException.Config("tls { echKeys } (kuicksilver.tls.echKeys) does not apply to $c")
                }
                @OptIn(ExperimentalKuicksilverApi::class)
                if (t.keyExchangeGroups != io.kuicksilver.tls.KeyExchangeGroups.Default) {
                    throw TlsException.Config("tls { keyExchangeGroups } (kuicksilver.tls.keyExchangeGroups) does not apply to $c")
                }
                // Ktor's sslConnector has no stapled OCSP response and no gateway exemption: tlsConnector { } has both. A gateway
                // exemption for the cleartext deployment port (no identity) is accepted next to it and stays on that port: the
                // sslConnector still answers 421 for hosts its certificate does not name
                @OptIn(ExperimentalKuicksilverApi::class)
                if (t.ocspStapling != null || (configuration.deploymentAllowMisdirectedHosts && engineTls.identity != null)) {
                    throw TlsException.Config(
                        "tls { ocspStapling } (kuicksilver.tls.ocspStapling) and kuicksilver.connector.allowMisdirectedHosts do " +
                            "not apply to $c: Ktor's sslConnector cannot express them; serve that port with tls { } " +
                            "(kuicksilver.tls.*), or use tlsConnector { } in code",
                    )
                }
                // nor the PROXY protocol, which must come before its TLS: a proxy sending headers there would be refused
                if (configuration.deploymentProxyProtocol != null) {
                    throw TlsException.Config(
                        "kuicksilver.connector.proxyProtocol applies to the deployment port, not to $c: Ktor's sslConnector cannot " +
                            "read a PROXY header; serve that port with the kuicksilver.tls keys, or use tlsConnector { proxyProtocol { } } in code",
                    )
                }
                platformTlsConnector(c)
                    ?.let { if (configuration.deploymentEveryInterface) it.withHost(everyInterfaceHost(c)) else it }
                    ?.let { Listener(it, it) }
                    ?: throw TlsException.Config(
                        "connector $c is not supported by the Kuicksilver engine: use tlsConnector { } or a plain connector",
                    )
            }
        }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private fun initServerJob(): Job {
        val stopRequest = stopRequest
        val startupJob = startupJob
        return CoroutineScope(applicationProvider().parentCoroutineContext + engineDispatcher).launch(start = CoroutineStart.LAZY) {
            serverScope = this
            // the leak sentinel's record of a started server (off in production: one read): it ends once the server job and
            // everything under it (listeners, connections, calls) ended
            val leak = LeakRegistry.open("server.engine")
            if (leak != 0L) coroutineContext[Job]!!.invokeOnCompletion { LeakRegistry.close(leak) }
            val servers = ArrayList<TcpServer>()
            val h3 = ArrayList<H3Listener>()
            try {
                try {
                    // the derived settings are refused and the files' identities made reloadable before anything binds
                    h3Quic = configuration.resolveQuic()
                    h3Settings = configuration.resolveHttp3Settings()
                    h2Settings = configuration.resolveHttp2Settings()
                    configuration.refuseDerivedEndpoint()
                    engineTls = configuration.tls.resolve("tls").also { resolvedTls += it }
                    val listeners = configuration.connectors.map { resolve(everyInterfaceOf(it)) }
                    // RFC 9113 section 9.2.2 for HTTP/2 over TLS 1.2, before anything binds
                    for (l in listeners) l.tls?.let { checkTls12H2(it, configuration.http2.enabled, log) }

                    // the PROXY protocol header's wait is cut to the request-head deadline: below 3 s it would be shorter than
                    // the spec's "at least 3 seconds to cover a TCP retransmit" (section 2)
                    val headDeadline = configuration.requestHeaderTimeout
                    if (headDeadline < ProxyProtocolConfig.MIN_HEADER_TIMEOUT && listeners.any { it.proxyProtocol != null }) {
                        val key =
                            if (configuration.deploymentProxyProtocol !=
                                null
                            ) {
                                "kuicksilver.connector.proxyProtocol"
                            } else {
                                "proxyProtocol { }"
                            }
                        throw IllegalArgumentException(
                            "$key needs a requestHeaderTimeout of at least ${ProxyProtocolConfig.MIN_HEADER_TIMEOUT} " +
                                "(it is $headDeadline): the PROXY protocol header's wait is cut to the request-head deadline",
                        )
                    }
                    // TCP accepting waits for the HTTP/3 listeners: h3Ports is complete (and published) before any connection reads it
                    val h3Ready = Job()
                    // one at a time: a connector whose set-up throws leaves those before it in [servers], so the failure path
                    // below stops them instead of leaving them accepting
                    for (l in listeners) servers += startTcp(this, l, h3Ready)
                    val resolved =
                        listeners.zip(servers).map { (l, s) ->
                            val port = (s.socket.await().localAddress as? InetSocketAddress)?.port ?: l.config.port
                            s.h3Endpoint.await()?.let { h3 += startHttp3(this, l.tls!!, it, port) }
                            when {
                                l.tls != null -> l.tls.withPort(port)
                                l.config is KuicksilverPlainConnector -> l.config.withPort(port)
                                else -> l.config.withPort(port)
                            }
                        }
                    h3Ready.complete()
                    resolvedConnectorsDeferred.complete(resolved)
                } catch (cause: Throwable) {
                    servers.forEach { it.rootJob.cancel() }
                    // connectors that never started are no part of the probe's count
                    servers.forEach { tcpConnectionsForProbe -= it.connections }
                    servers.forEach { tcpLimitsForProbe -= it.limits }
                    // an endpoint bound next to its TCP socket but not yet serving (another connector failed) is closed here
                    servers.forEach { srv ->
                        runCatching { srv.h3Endpoint.getCompleted() }.getOrNull()?.let { e -> if (h3.none { it.endpoint === e }) e.close() }
                    }
                    h3.forEach {
                        it.acceptJob.cancel()
                        it.connections.cancel()
                    }
                    stopRequest.completeExceptionally(cause)
                    startupJob.completeExceptionally(cause)
                    // the failure reaches the caller through startupJob; rethrowing it here would make it an uncaught coroutine exception, which terminates a Kotlin/Native process (seen on Linux arm64)
                    if (cause is CancellationException) throw cause else return@launch
                }
                startedH3Endpoints = h3.map { it.endpoint }
                startIdentityWatcher() // before the start completes: its startup checks (the OCSP response) are logged by then
                startupJob.complete(Unit)
                stopRequest.join()
                stopIdentityWatcher()
                // graceful stop (RFC 9114 5.2): no new connections or requests, GOAWAY to every live HTTP/3 connection, then wait for the
                // in-flight calls; `stopSuspend` cancels this job at the grace deadline, which closes what is left
                servers.forEach {
                    it.acceptJob.cancel()
                    // before ApplicationStopPreparing: a response written from here on says Connection: close
                    it.draining.complete()
                }
                // every connection at once: goAway() waits 2×RTT between its two frames, one after another the k-th would wait k×50 ms
                h3.forEach { l ->
                    // HTTP/3 accepting goes on: handshakes in flight complete, and those connections get GOAWAY at once
                    l.stopping = true
                    // the QUIC side of the grace period: new clients refused at their first Initial, the live connections get
                    // the grace period to finish, then whatever is left closes with H3_NO_ERROR; once none is left the
                    // endpoint closes, which ends accepting
                    launch {
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        runCatching { l.endpoint.shutdown(stopGraceMillis.milliseconds) }
                    }
                    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                    for (c in l.live()) launch { runCatching { stopGoAway(c) } }
                }
                withContext(userDispatcher) { monitor.raise(ApplicationStopPreparing, environment) }
                servers.map { it.rootJob }.joinAll()
                h3.forEach { l ->
                    l.acceptJob.join()
                    l.connections.children
                        .toList()
                        .joinAll()
                }
            } finally {
                withContext(NonCancellable) {
                    h3.forEach { l ->
                        // the endpoint first: what is left gets CONNECTION_CLOSE with H3_NO_ERROR, not a stream reset per call
                        l.endpoint.close()
                        l.connections.cancel()
                    }
                    stopIdentityWatcher()
                    // an identity read from files (tls { pemFiles }) is the engine's: its native key goes with the engine
                    // (connections still closing keep their own reference in their contexts)
                    resolvedTls.forEach { t -> runCatching { t.closeOnStop?.close() } }
                }
            }
        }
    }

    /**
     * The file watchers of `tls { reloadInterval }` (the identity's files, the client CA file and the OCSP response file of
     * every TLS the engine resolved) from startup until the stop begins; null without one. It runs outside the server job:
     * a check stuck in a read that cannot be interrupted (a hung network file system, a FIFO at the path) must not keep the
     * server job, and so the stop, from completing.
     */
    @Volatile
    private var identityWatcher: Job? = null

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun startIdentityWatcher() {
        val runs = ArrayList<suspend CoroutineScope.() -> Unit>()
        for (t in resolvedTls) {
            val interval = t.reloadInterval
            // the OCSP response file: whether it is stapled is logged now, and again when that changes (checked every reload
            // interval, re-reading the file, or hourly without one: a response expires)
            val ocsp =
                t.ocspFile?.let { path ->
                    val stapling = t.ocspStapling ?: return@let null
                    val id = t.identity ?: return@let null
                    OcspFileWatcher(path, stapling, { id.chain }, log, reread = interval != null)
                }
            ocsp?.checkUsable()
            if (ocsp != null) runs += { ocsp.run(interval ?: 1.hours) }
            if (interval == null) continue
            val readText = t.readText
            val identity =
                t.identityFiles?.let { (chain, key) ->
                    t.reloadableIdentity?.let { target ->
                        if (readText == null) {
                            IdentityFileWatcher(chain, key, target, log, settle = t.settle)
                        } else {
                            IdentityFileWatcher(chain, key, target, log, readText = readText, settle = t.settle)
                        }
                    }
                }
            val clientCa =
                t.clientCaFile?.let { path ->
                    t.reloadableCa?.let { target -> ClientCaFileWatcher(path, target, log, settle = t.settle) }
                }
            if (identity != null) runs += { identity.run(interval) }
            if (clientCa != null) runs += { clientCa.run(interval) }
        }
        if (runs.isEmpty()) return
        identityWatcher = CoroutineScope(engineDispatcher).launch { runs.forEach { r -> launch { r() } } }
    }

    /**
     * Cancels the watcher and waits for it at most a second: a check blocked in a read finishes on its own later, and closing
     * the identity meanwhile is safe (a reload after close is refused, a context being built keeps its own key reference).
     */
    private suspend fun stopIdentityWatcher() {
        val w = identityWatcher ?: return
        w.cancel()
        withTimeoutOrNull(1.seconds) { w.join() }
    }

    /** The PEM file watcher, for tests. */
    internal val identityWatcherForTest: Job? get() = identityWatcher

    /** TCP ports whose UDP twin serves HTTP/3: only those advertise it with Alt-Svc. Written at startup before TCP accepting begins, read-only after. */
    internal val h3Ports = HashSet<Int>()

    /** TCP ports whose HTTP/3 is not served for one address family (no DF for it): its connections advertise no Alt-Svc. */
    internal val h3NoDfFamily = HashMap<Int, io.kuicksilver.quic.IpFamily>()
    internal val h3Endpoints = ArrayList<Http3Endpoint>()

    /** The HTTP/3 listeners and the supervisors of the TCP connection handlers, for [KuicksilverServerProbe]; written at startup. */
    internal val h3ListenersForProbe = ArrayList<H3Listener>()

    /** Test hook: runs in the HTTP/3 accept loop after each accepted connection, before it is served. */
    internal var afterH3AcceptForTest: (suspend () -> Unit)? = null

    /** Test hook: sees each accepted HTTP/3 connection, after [afterH3AcceptForTest] and before it is served. */
    internal var h3ConnectionForTest: ((Http3Connection) -> Unit)? = null

    /** Test hook: runs in each HTTP/3 request's handler coroutine before the request is handled; a suspension here holds it. */
    internal var beforeH3HandlerForTest: (suspend () -> Unit)? = null

    /** Test hook: runs when an HTTP/3 connection accepts no more requests, while the requests it accepted may still run. */
    internal var afterH3RequestsAcceptedForTest: (() -> Unit)? = null

    /** Test hook: runs as an HTTP/3 WebSocket upgrade starts, after Ktor committed the response, before the answer is sent. */
    internal var beforeH3UpgradeForTest: (() -> Unit)? = null
    internal val tcpConnectionsForProbe = ArrayList<Job>()

    /** Live HTTP/2 connections, for [KuicksilverServerProbe] and tests. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal val h2Live = H2LiveSet()

    /** Accepted TCP sockets whose descriptor is not released yet (their job completes when it is); for tests. */
    internal val openTcpSockets = kotlinx.coroutines.flow.MutableStateFlow(0)

    /**
     * Client addresses whose HTTP/2 connections keep ending in a flood defence, refused at accept for a while; null unless
     * `http2 { repeatOffenderPenalty }` is set.
     */
    @kotlin.concurrent.Volatile
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    internal var h2Offenders: RepeatOffenders? = configuration.http2.repeatOffenderPenalty?.let { RepeatOffenders(it) }

    /** Bytes the HTTP/2 layer of ended connections read from their clients, in all; for tests. */
    internal val h2BytesRead = kotlinx.coroutines.flow.MutableStateFlow(0L)

    /** HTTP/2 connections that ended in a flood defence (we sent ENHANCE_YOUR_CALM); for tests. */
    internal val h2FloodEnds = kotlinx.coroutines.flow.MutableStateFlow(0L)

    /** TCP connections closed at accept because their address serves an HTTP/2 penalty ([h2Offenders]); for tests. */
    internal val refusedOffenders = kotlinx.coroutines.flow.MutableStateFlow(0L)

    /** The connection limits of every TCP connector, for [KuicksilverServerProbe]; written at startup. */
    internal val tcpLimitsForProbe = ArrayList<TcpLimits>()

    /** TCP connections closed at accept because their address held `tcp { maxConnectionsPerIp }` ([TcpLimits]). */
    internal val refusedPerIp = kotlinx.coroutines.flow.MutableStateFlow(0L)
}

/** `EngineSSLConnectorConfig` (JVM `sslConnector {}`) as a Kuicksilver connector; null on platforms without it. */
internal expect fun platformTlsConnector(c: EngineConnectorConfig): KuicksilverTlsConnector?

/**
 * The Ktor artifacts the server engine depends on beyond public API (docs/ktor-internal-api.md) or vendors code of, each
 * with a class it contains, for the startup version check: the server core, the HTTP/1.1 parser, the sockets (adapted on
 * Native, `kuicksilver-ktor-network`) and the I/O channels (`readBuffer`, `@InternalAPI` channel operations).
 */
internal val KTOR_ARTIFACTS: List<Pair<String, kotlin.reflect.KClass<*>>> =
    listOf(
        "ktor-server-core" to io.ktor.server.engine.BaseApplicationEngine::class,
        "ktor-http-cio" to io.ktor.http.cio.Request::class,
        "ktor-network" to io.ktor.network.selector.SelectorManager::class,
        "ktor-io" to io.ktor.utils.io.ByteReadChannel::class,
    )
