// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
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
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.ktor.server.h1.installH1CallHandling
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
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The Kuicksilver server engine (docs/guide/ktor.md): HTTP/1.1 over TLS on TCP through the CIO connection pipeline of Ktor
 * (HTTP/2 there too when `http2` is set), and HTTP/3 on UDP on the same port. Start it with `embeddedServer(Kuicksilver, ...)`.
 */
public class KuicksilverApplicationEngine(
    environment: ApplicationEnvironment,
    monitor: Events,
    developmentMode: Boolean,
    /** The engine settings and connectors this engine was created with; read when it starts. */
    public val configuration: Configuration,
    internal val applicationProvider: () -> Application,
) : BaseApplicationEngine(environment, monitor, developmentMode) {
    /** Engine settings; HTTP/3 knobs follow the names of Ktor's Netty engine where one exists. */
    public class Configuration : BaseApplicationEngine.Configuration() {
        /**
         * Seconds an HTTP/1.1 connection stays open without a request: then it is closed, both directions. On a keep-alive
         * connection [requestHeaderTimeoutSeconds] also runs from the end of the last response, so the smaller of the two
         * closes an idle connection. A response the client reads nothing of (its socket takes nothing) ends the connection
         * after the longer of this and 5 minutes: the engine sees a client's reading progress about 1 MiB at a time (the
         * buffer in front of the socket), and 1 MiB in 5 minutes keeps clients down to about 3.4 KiB/s. A closing
         * connection sends what is left for as long as the client takes it, and is aborted after the same time without
         * progress. A request body that sends no byte for this long (counted after `100 Continue` when the client asked
         * for it) fails the handler's read; the client gets 408 when no response has started, and the connection closes.
         * Each wait for body bytes has its own deadline, so a slow but moving upload is read in full.
         */
        public var connectionIdleTimeoutSeconds: Int = 45

        /**
         * Seconds a client has to send a complete HTTP/1.1 request head (request line and header fields), counted from the
         * accepted TCP connection for the first request (the TLS handshake included) and from the end of the previous
         * response for the next one on a keep-alive connection; bytes that trickle in do not extend it. A client that sent
         * part of a head by then gets `408 Request Timeout` and the connection closes; one that sent nothing (an idle
         * keep-alive connection, or a connection that never spoke) is closed without a response. Positive; default 30.
         *
         * @throws IllegalArgumentException when set to zero or less.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var requestHeaderTimeoutSeconds: Int = 30
            set(value) {
                require(value > 0) { "requestHeaderTimeoutSeconds must be positive" }
                field = value
            }

        /**
         * The most TCP connections each connector holds at once, HTTP/1.1 and HTTP/2 alike, counted from `accept` (TLS
         * handshakes included) until the socket is released. At the limit the connector stops accepting: the OS backlog
         * holds new clients (their connect succeeds, nothing is read from them) until a connection closes, and the server
         * spends no descriptor or TLS work on them. When the backlog is full too (511 on the JVM, 50 on Kotlin/Native) the
         * OS drops further connection attempts (Linux by default; the client's TCP retries them) or resets them. The
         * default does not protect a process whose descriptor limit is lower (`ulimit -n`: 256 in a macOS shell, often
         * 1024 on Linux): raise that limit or set this below it (docs/guide/ktor.md, "Connection limits"). At least 1;
         * default 10,000. `EngineMain` key `kuicksilver.maxTcpConnections`.
         *
         * @throws IllegalArgumentException when set below 1.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var maxTcpConnections: Int = 10_000
            set(value) {
                require(value >= 1) { "maxTcpConnections must be at least 1" }
                field = value
            }

        /**
         * The most TCP connections one client address holds at once on a connector, HTTP/1.1 and HTTP/2 alike; null (the
         * default) turns the limit off. Behind a reverse proxy, a load balancer, Kubernetes source NAT or any NAT every
         * client shares one address, and an HTTP/1.1 proxy opens an upstream connection per request in flight (and one per
         * WebSocket or SSE stream): enable it (256, say) only when the server faces its clients directly. A connection over
         * it is reset right after `accept`, before its TLS handshake (its address is not known earlier), which a proxy in
         * front reports as 502 or 503, and it is reported to [KuicksilverServerEventListener.connectionRefused] with the
         * reason `per-IP limit`. An address is its bytes, never a name: an IPv4-mapped client as its IPv4 address, an IPv6
         * client by its whole address (as QUIC `maxConnectionsPerIp`), so a client holding a /64 gets around it. At least
         * 1, or null. `EngineMain` key `kuicksilver.maxTcpConnectionsPerIp` (`0` or absent is off).
         *
         * @throws IllegalArgumentException when set below 1.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var maxTcpConnectionsPerIp: Int? = null
            set(value) {
                require(value == null || value >= 1) { "maxTcpConnectionsPerIp must be at least 1, or null" }
                field = value
            }

        /**
         * When set, every plain connector (`port = ...` of embeddedServer, `connector {}`) serves TLS with this identity instead.
         * A `TlsIdentity.Reloadable` lets the certificate be replaced while the server runs (docs/guide/ktor.md, "Certificate
         * rotation").
         */
        public var identity: TlsIdentity? = null

        /**
         * How often `EngineMain` looks at the PEM files of `kuicksilver.tls.certificateChain` and `kuicksilver.tls.privateKey`
         * for a renewed certificate (configuration key `kuicksilver.tls.reloadInterval`, e.g. `1h`); null (the default) reads
         * them once at startup. A new chain is applied once two reads a second apart agree and the key matches it; a failure
         * keeps the identity in use, is logged, and is retried after 1 s, then twice as long each time up to this interval.
         * New handshakes get the new certificate, running connections keep theirs (docs/guide/ktor.md, "Certificate
         * rotation"). The client CA file of `kuicksilver.tls.clientCa`, when set, is watched at the same interval and by the
         * same rules: new handshakes verify client certificates against the new bundle. It needs those two keys: the server
         * refuses to start with it set otherwise. At least 1 second.
         *
         * @throws IllegalArgumentException when set below 1 second.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var identityReloadInterval: Duration? = null
            set(value) {
                require(value == null || value >= 1.seconds) { "identityReloadInterval must be at least 1 second" }
                field = value
            }

        /** The PEM files [identity] was read from, set by `EngineMain`; the files [identityReloadInterval] watches. */
        internal var identityFiles: Pair<String, String>? = null

        /** Set by `EngineMain`, which made [identity] from its files: the engine closes it when it stops. */
        internal var closeIdentityOnStop: Boolean = false

        /** Tests shorten the watcher's settle time (two equal reads of a changed chain) with this; null keeps 1 s. */
        internal var identitySettleForTest: Duration? = null

        /** Tests replace how the watcher reads the chain file (a read that never returns, say); null reads the file. */
        internal var identityReadTextForTest: ((String) -> String)? = null

        /** Set by `EngineMain` (`kuicksilver.tls.clientAuth`): whether the connectors [identity] serves ask for a client certificate. */
        internal var clientAuth: ClientAuth = ClientAuth.None

        /**
         * Set by `EngineMain` (`kuicksilver.tls.clientCa`): verifies client certificates on the connectors [identity] serves; a
         * `TrustConfig.ReloadableCa` when [identityReloadInterval] is set.
         */
        internal var clientTrust: TrustConfig? = null

        /** The PEM file [clientTrust] was read from, set by `EngineMain`; watched with [identityReloadInterval]. */
        internal var clientCaFile: String? = null

        /** Set by `EngineMain` (`kuicksilver.tls.versions`): the TLS versions of the connectors [identity] serves. */
        internal var tlsVersions: TlsVersions = TlsVersions.Tls13

        /**
         * Announce HTTP/3 with `h3=":<port>"; ma=86400` over TLS (on by default): an `Alt-Svc` field on HTTP/1.1 and HTTP/2
         * responses, and on HTTP/2 also an ALTSVC frame per origin and value on each connection, refreshed every 12 hours
         * (RFC 7838 sections 3 and 4).
         */
        public var altSvc: Boolean = true

        /** Serve HTTP/3 on UDP on the port of every TLS connector. */
        public var http3: Boolean = true

        /**
         * Serve HTTP/2 (RFC 9113) on TLS connectors: ALPN offers `h2` before `http/1.1`, so a client that offers both gets
         * HTTP/2 (docs/guide/ktor.md, "HTTP/2 on the server"). Off by default in 0.3.0, so the ALPN of a TLS connector stays
         * `http/1.1` unless this is set. Plain connectors never serve HTTP/2 (no h2c: a client's `PRI *` preface is
         * answered `505 HTTP Version Not Supported`, as before). Over TLS 1.3, and over TLS 1.2 on a connector that allows it
         * (`versions = TlsVersions.Tls12And13`; RFC 9113 section 9.2).
         * WebSockets come over HTTP/2 too (RFC 8441), unless [webSocketsOverHttp2] is turned off.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var http2: Boolean = false

        /**
         * Accept WebSockets over HTTP/2 (RFC 8441) on the connections of [http2]: their SETTINGS carry
         * `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`, and an Extended CONNECT with `:protocol = websocket` reaches Ktor's
         * `webSocket {}` routes as an upgrade request, answered `:status 200` (docs/guide/ktor.md, "WebSockets over HTTP/2").
         * On by default, as [webSocketsOverHttp3]; it has no effect while [http2] is off. When false the parameter is not
         * sent, and a client keeps opening its WebSockets over HTTP/1.1. `EngineMain` key `kuicksilver.webSocketsOverHttp2`.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var webSocketsOverHttp2: Boolean = true

        /**
         * The HTTP/2 SETTINGS, windows and flood limits of every HTTP/2 connection (`Http2Settings()` until assigned). The
         * engine bounds `maxHeaderBlockTime` by [requestHeaderTimeoutSeconds]: a field block slower than the smaller of
         * the two ends the connection.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var http2Settings: io.kuicksilver.http2.Http2Settings = io.kuicksilver.http2.Http2Settings()

        /**
         * Off ([Duration.ZERO], the default): each HTTP/2 connection that breaks a flood limit of [http2Settings] is ended
         * with GOAWAY ENHANCE_YOUR_CALM, and that is all. Positive: a client address whose HTTP/2 connections end that way
         * three times within a minute has its TCP connections (HTTP/1.1 too) closed at accept, before the TLS handshake,
         * for this long (docs/guide/ktor.md, "HTTP/2 on the server"; threat model 3.23). An IPv6 client counts by its /56,
         * an IPv4-mapped one by its IPv4 address; a slow field block is not a strike. Enable it only where the server sees
         * the real address of each client (directly exposed, or behind a proxy that keeps client addresses, such as one
         * that preserves the source IP): behind a NAT, a load balancer that rewrites source addresses (SNAT, Kubernetes
         * `externalTrafficPolicy: Cluster`) or a TCP proxy, every client shares the proxy's address and one flooder locks
         * them all out. `EngineMain` key `kuicksilver.http2RepeatOffenderPenalty` (a duration such as `30s`; `0` is off).
         *
         * @throws IllegalArgumentException when set to a negative duration.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var http2RepeatOffenderPenalty: Duration = Duration.ZERO
            set(value) {
                require(!value.isNegative()) { "http2RepeatOffenderPenalty must not be negative" }
                field = value
            }

        /**
         * QUIC transport settings of the HTTP/3 listener; [QuicConfig.Default] until assigned. With [http3] on,
         * `maxUniStreams` must be at least 3 (RFC 9114 section 6.2): a smaller value fails the start with
         * IllegalArgumentException.
         */
        public var quic: QuicConfig = QuicConfig.Default
            set(value) {
                field = value
                quicAssigned = true
            }

        /** Whether [quic] was assigned (any value, [QuicConfig.Default] included): then [quicMaxIdleTimeout] is not used. */
        internal var quicAssigned: Boolean = false
            private set

        /**
         * `quic.maxIdleTimeout` while [quic] is not assigned (the name follows Ktor-Netty). Once [quic] is assigned, before or
         * after this, its own `maxIdleTimeout` applies and this is ignored, also when the assigned value is [QuicConfig.Default].
         */
        public var quicMaxIdleTimeout: Duration? = null

        /**
         * Endpoint loops on the UDP port, as Ktor-Netty's `udpSocketCount`, on every platform with a QUIC server: a socket per
         * loop with kernel `SO_REUSEPORT` flow hashing on Linux and Android, one socket whose datagrams are routed to the
         * loops by connection ID in process on macOS, iOS and Windows (docs/guide/quic.md, "Several loops on one port").
         * One connection runs on one loop. Where the accelerated socket cannot open (a JVM on the portable socket), more
         * than 1 cannot run: the engine logs why and serves HTTP/1.1 only on that connector.
         */
        public var udpSocketCount: Int = 1

        /**
         * The most QUIC connections each HTTP/3 listener holds at once, handshakes in flight included, over all its
         * [udpSocketCount] loops together (`QuicEndpointConfig.maxConnections`): beyond it a new client's Initial is dropped silently and counted in
         * `EndpointStats.connectionsRefusedLimits` ([KuicksilverApplicationEngine.http3Stats]). At least 1; default 10,000.
         * `EngineMain` key `kuicksilver.quicMaxConnections`.
         *
         * @throws IllegalArgumentException when set below 1.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var quicMaxConnections: Int = 10_000
            set(value) {
                require(value >= 1) { "quicMaxConnections must be at least 1" }
                field = value
            }

        /**
         * The most QUIC connections one client IP holds at once on each HTTP/3 listener, over all its [udpSocketCount] loops
         * together, ports ignored (`QuicEndpointConfig.maxConnectionsPerIp`); null turns the limit off. Beyond it a new client's Initial is dropped
         * silently (the client fails at its handshake timeout) and counted in `EndpointStats.connectionsRefusedLimits`.
         * Behind a NAT, Kubernetes `kube-proxy` with `externalTrafficPolicy: Cluster`, or a UDP load balancer that does not
         * keep client addresses, every client shares one address: raise it to about [quicMaxConnections] there, or turn
         * it off (docs/guide/deployment.md, "QUIC connection limits"). At least 1, or null; default 256. `EngineMain` key
         * `kuicksilver.quicMaxConnectionsPerIp` (`0` is off).
         *
         * @throws IllegalArgumentException when set below 1.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var quicMaxConnectionsPerIp: Int? = 256
            set(value) {
                require(value == null || value >= 1) { "quicMaxConnectionsPerIp must be at least 1, or null" }
                field = value
            }

        /**
         * Handshaken QUIC connections waiting for the engine's HTTP/3 accept loop on each listener, all its loops together
         * (`QuicEndpointConfig.acceptQueue`): while this many wait, a new client is refused at once with CONNECTION_REFUSED,
         * counted in `EndpointStats.connectionsRefusedAcceptQueue`. At least 1; default 128. `EngineMain` key
         * `kuicksilver.quicAcceptQueue`.
         *
         * @throws IllegalArgumentException when set below 1.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var quicAcceptQueue: Int = 128
            set(value) {
                require(value >= 1) { "quicAcceptQueue must be at least 1" }
                field = value
            }

        /** Admission of new QUIC connections (Retry above a handshake threshold by default); Ktor-Netty's `quicTokenHandler`. */
        public var quicAdmission: ConnectionAdmission? = null

        /**
         * The QUIC-LB configuration of every HTTP/3 listener's connection IDs (`QuicEndpointConfig.loadBalancer`,
         * draft-ietf-quic-load-balancers-21; docs/guide/quic.md, "Behind a load balancer"); null (the default) for none. Its
         * `QuicLbConfig.connectionIdLength` must equal `quic.connectionIdLength`. Change it on the running engine with
         * [KuicksilverApplicationEngine.updateLoadBalancer].
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var quicLoadBalancer: io.kuicksilver.quic.QuicLbConfig? = null

        /** HTTP/3 settings (QPACK, limits). Extended CONNECT is turned on by [webSocketsOverHttp3]. */
        public var http3Settings: Http3Settings = Http3Settings.Default

        /**
         * Accept WebSockets over HTTP/3 (RFC 9220): advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. When false, a WebSocket
         * Extended CONNECT is answered 501 (RFC 9220 section 3), also while [webTransport] advertises Extended CONNECT.
         */
        public var webSocketsOverHttp3: Boolean = true

        /**
         * The largest WebSocket message, and so frame, the server takes from a client, in bytes (RFC 6455 section 10.4: an
         * implementation "SHOULD impose a limit on frame sizes and the total message size after reassembly"); 16 MiB by
         * default, as `PerMessageDeflate`'s `maxInflatedMessageSize`. A frame whose header claims more, or that takes its
         * message past it, closes the connection with 1009 (message too big) before any of its payload is read; a
         * compressed message is held to the smaller of this and the extension's limit, counted inflated. Over HTTP/1.1,
         * HTTP/2 and HTTP/3 alike; Ktor's `WebSockets { maxFrameSize }` applies on top of it.
         *
         * @throws IllegalArgumentException when set below 1.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var webSocketMaxMessageSize: Long = 16_777_216L // 16 MiB
            set(value) {
                require(value >= 1) { "webSocketMaxMessageSize must be at least 1" }
                field = value
            }

        /**
         * Serve WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16) to `webTransport(path) { }` routes: turns on
         * `Http3Settings.webTransport` and `enableConnectProtocol`; false by default. Needs QUIC datagrams (the default
         * `quic` has them): the engine refuses to start otherwise.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var webTransport: Boolean = false

        /**
         * Accept 0-RTT on HTTP/3 (off by default; ADR-0015). Early requests can be replayed by an attacker: by default only
         * GET, HEAD and OPTIONS run before the handshake completes (`http3Settings.earlyData` decides), every other request
         * waits for it. Handlers of early requests must be free of side effects; see `ApplicationRequest.receivedEarly`. A
         * request a gateway marked `Early-Data` (RFC 8470 section 5.1) is treated as early whatever this setting.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var quicEarlyData: Boolean = false

        /**
         * Where the HTTP/3 endpoints' diagnostics go (docs/guide/quic.md, "Observability"); null (the default) keeps the QUIC
         * endpoint's default, `KuicksilverLogger.Stderr` (warnings on standard error), as the client engine's `logger` does.
         * The engine's own messages keep going to the application's log.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var logger: KuicksilverLogger? = null

        /**
         * A qlog trace per HTTP/3 connection, added to [quic]; null (the default) keeps that configuration's own. Wrap a file
         * sink in `AsyncQlogSink` so a slow disk never stalls the endpoint: `qlog = AsyncQlogSink(DirectoryQlogSink(dir))`.
         */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var qlog: QlogSink? = null

        /** Hears the lifecycle of every QUIC connection of the HTTP/3 listeners (`QuicEndpointConfig.listener`); null for none. */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var connectionListener: ConnectionListener? = null

        /** Hears connections and requests over HTTP/1.1 and HTTP/3 (docs/guide/ktor.md, "Observability"); null for none. */
        @io.kuicksilver.annotations.ExperimentalKuicksilverApi
        public var eventListener: KuicksilverServerEventListener? = null

        /** Tests shorten the HTTP/1.1 send-stall deadline with this; null keeps the engine's own. */
        internal var sendStallTimeoutForTest: Duration? = null

        /** Tests drive the HTTP/2 connections' clock (monotonic nanoseconds: reset budgets, protocol deadlines) with this. */
        internal var h2ClockForTest: (() -> Long)? = null

        /** How the HTTP/3 listener binds (tests replace it to simulate platforms without a QUIC server). */
        internal var http3Bind: suspend (
            InetSocketAddress,
            QuicEndpointConfig,
            Http3Settings,
        ) -> Http3Endpoint = { a, c, s -> Http3Endpoint.bind(a, c, s) }

        /** Adds a TLS connector (HTTP/1.1 over TLS plus HTTP/3 on the same port). */
        public fun tlsConnector(
            identity: TlsIdentity,
            block: KuicksilverTlsConnector.Builder.() -> Unit = {},
        ) {
            connectors.add(KuicksilverTlsConnector.Builder(identity).apply(block).build())
        }

        /**
         * Adds a plain HTTP/1.1 connector, as Ktor's `connector { }`, with the option of marking its clients trusted gateways
         * ([KuicksilverPlainConnector.Builder.trustedGateway]).
         */
        @ExperimentalKuicksilverApi
        public fun plainConnector(block: KuicksilverPlainConnector.Builder.() -> Unit = {}) {
            connectors.add(KuicksilverPlainConnector.Builder().apply(block).build())
        }
    }

    /** The configuration's [KuicksilverServerEventListener], behind a guard that logs its failures. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    internal val events = ServerEvents(configuration.eventListener, environment.log)

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
     * Moves every HTTP/3 listener to another QUIC-LB configuration ([quicLoadBalancer][Configuration.quicLoadBalancer] must have
     * been set). Waits for the start first, so every listener is there; checks [config] against every listener before it
     * changes any, so a refused configuration leaves them all as they were.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public suspend fun updateLoadBalancer(config: io.kuicksilver.quic.QuicLbConfig?) {
        check(configuration.quicLoadBalancer != null) { "updateLoadBalancer needs quicLoadBalancer in the engine configuration" }
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
        monitor.raiseCatching(ServerReady, environment, environment.log)
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
    ) {
        /** Every client is a trusted gateway: no request is rejected as misdirected (RFC 9110 section 7.4). */
        @OptIn(ExperimentalKuicksilverApi::class)
        val trustedGateway: Boolean = tls?.trustedGateway ?: (config as? KuicksilverPlainConnector)?.trustedGateway ?: false
    }

    private fun resolve(c: EngineConnectorConfig): Listener =
        when {
            c is KuicksilverTlsConnector -> {
                Listener(c, c)
            }

            c.type == ConnectorType.HTTP -> {
                configuration.identity?.let { id ->
                    KuicksilverTlsConnector
                        .Builder(id)
                        .apply {
                            host = c.host
                            port =
                                c.port
                            clientAuth = configuration.clientAuth
                            trust = configuration.clientTrust
                            @OptIn(ExperimentalKuicksilverApi::class)
                            trustedGateway = (c as? KuicksilverPlainConnector)?.trustedGateway ?: false
                            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                            versions = configuration.tlsVersions
                        }.build()
                        .let { Listener(it, it) }
                }
                    ?: Listener(c, null)
            }

            else -> {
                // Ktor's sslConnector (JVM `-sslPort`, `ktor.security.ssl.*`) takes client certificates from its own trustStore:
                // EngineMain's client CA keys would silently not apply to it, so the combination is refused
                if (configuration.clientTrust != null) {
                    throw TlsException.Config(
                        "kuicksilver.tls.clientAuth and kuicksilver.tls.clientCa apply to the port of kuicksilver.tls.certificateChain, " +
                            "not to $c: use ktor.security.ssl.trustStore there, or serve only the kuicksilver.tls port",
                    )
                }
                // the same for the TLS versions: Ktor's own key for that connector is ktor.security.ssl.enabledProtocols
                if (configuration.tlsVersions != TlsVersions.Tls13) {
                    throw TlsException.Config(
                        "kuicksilver.tls.versions applies to the port of kuicksilver.tls.certificateChain, not to $c: " +
                            "use ktor.security.ssl.enabledProtocols there",
                    )
                }
                platformTlsConnector(c)?.let { Listener(it, it) }
                    ?: throw TlsException.Config(
                        "connector $c is not supported by the Kuicksilver engine: use tlsConnector(identity) or a plain connector",
                    )
            }
        }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    private fun initServerJob(): Job {
        val stopRequest = stopRequest
        val startupJob = startupJob
        return CoroutineScope(applicationProvider().parentCoroutineContext + engineDispatcher).launch(start = CoroutineStart.LAZY) {
            serverScope = this
            val servers = ArrayList<TcpServer>()
            val h3 = ArrayList<H3Listener>()
            try {
                try {
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    if (configuration.identityReloadInterval != null) {
                        require(configuration.identityFiles != null && configuration.identity is TlsIdentity.Reloadable) {
                            "identityReloadInterval watches the PEM files of kuicksilver.tls.certificateChain and " +
                                "kuicksilver.tls.privateKey (EngineMain); without them call TlsIdentity.Reloadable.reload yourself"
                        }
                    }
                    val listeners = configuration.connectors.map { resolve(it) }
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
                startupJob.complete(Unit)
                startIdentityWatcher()
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
                    for (c in l.live()) launch { runCatching { c.goAway(stopCloseFallback) } }
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
                    // an identity EngineMain made from its files is the engine's: its native key goes with the engine (connections
                    // still closing keep their own reference in their contexts)
                    if (configuration.closeIdentityOnStop) (configuration.identity as? AutoCloseable)?.close()
                }
            }
        }
    }

    /**
     * The PEM file watchers of [Configuration.identityReloadInterval] (the identity's files and the client CA file) from startup
     * until the stop begins; null without one. It runs
     * outside the server job: a check stuck in a read that cannot be interrupted (a hung network file system, a FIFO at the path)
     * must not keep the server job, and so the stop, from completing.
     */
    @Volatile
    private var identityWatcher: Job? = null

    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun startIdentityWatcher() {
        val interval = configuration.identityReloadInterval ?: return
        val settle = configuration.identitySettleForTest ?: 1.seconds
        val readText = configuration.identityReadTextForTest
        val identity =
            configuration.identityFiles?.let { (chain, key) ->
                (configuration.identity as? TlsIdentity.Reloadable)?.let { target ->
                    if (readText == null) {
                        IdentityFileWatcher(chain, key, target, environment.log, settle = settle)
                    } else {
                        IdentityFileWatcher(chain, key, target, environment.log, readText = readText, settle = settle)
                    }
                }
            }
        val clientCa =
            configuration.clientCaFile?.let { path ->
                (configuration.clientTrust as? TrustConfig.ReloadableCa)?.let { target ->
                    ClientCaFileWatcher(path, target, environment.log, settle = settle)
                }
            }
        if (identity == null && clientCa == null) return
        identityWatcher =
            CoroutineScope(engineDispatcher).launch {
                identity?.let { launch { it.run(interval) } }
                clientCa?.let { launch { it.run(interval) } }
            }
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
    internal val h3Endpoints = ArrayList<Http3Endpoint>()

    /** The HTTP/3 listeners and the supervisors of the TCP connection handlers, for [KuicksilverServerProbe]; written at startup. */
    internal val h3ListenersForProbe = ArrayList<H3Listener>()

    /** Test hook: runs in the HTTP/3 accept loop after each accepted connection, before it is served. */
    internal var afterH3AcceptForTest: (suspend () -> Unit)? = null

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
     * [Configuration.http2RepeatOffenderPenalty] is positive.
     */
    @kotlin.concurrent.Volatile
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    internal var h2Offenders: RepeatOffenders? =
        configuration.http2RepeatOffenderPenalty.takeIf { it.isPositive() }?.let { RepeatOffenders(it) }

    /** Bytes the HTTP/2 layer of ended connections read from their clients, in all; for tests. */
    internal val h2BytesRead = kotlinx.coroutines.flow.MutableStateFlow(0L)

    /** HTTP/2 connections that ended in a flood defence (we sent ENHANCE_YOUR_CALM); for tests. */
    internal val h2FloodEnds = kotlinx.coroutines.flow.MutableStateFlow(0L)

    /** TCP connections closed at accept because their address serves an HTTP/2 penalty ([h2Offenders]); for tests. */
    internal val refusedOffenders = kotlinx.coroutines.flow.MutableStateFlow(0L)

    /** The connection limits of every TCP connector, for [KuicksilverServerProbe]; written at startup. */
    internal val tcpLimitsForProbe = ArrayList<TcpLimits>()

    /** TCP connections closed at accept because their address held `maxTcpConnectionsPerIp` ([TcpLimits]). */
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
