// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.HttpClientEngineConfig
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.KeylogSink
import io.kuicksilver.tls.RevocationPolicy
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CoroutineDispatcher
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** When `https://` requests use HTTP/3 (after JDK 26 `Http3DiscoveryMode` and Cronet's QUIC hints); `http3 { enabled = false }` turns HTTP/3 off. */
public enum class Http3Discovery {
    /** TCP first (HTTP/2 or HTTP/1.1); HTTP/3 once the origin advertised it with `Alt-Svc` (RFC 7838). The default. */
    Auto,

    /** HTTP/3 by prior knowledge, falling back to TCP (like `curl --http3`). */
    Preferred,

    /** HTTP/3 only, no fallback (like `curl --http3-only`). */
    H3Only,
}

/**
 * A host and port, for [Http3ClientConfig.hints], [Http2ClientConfig.priorKnowledge] and [KnownServers.Listed].
 *
 * @property host the host exactly as in request URLs (compared as is, no case folding or resolution).
 * @property port the port, the scheme's default (443 for `https`, 80 for `http`) for URLs without one.
 */
public class HostPort(
    public val host: String,
    public val port: Int,
) {
    /** Equal when the host and the port are. */
    override fun equals(other: Any?): Boolean = other is HostPort && other.host == host && other.port == port

    /** Consistent with [equals]. */
    override fun hashCode(): Int = host.hashCode() * 31 + port

    /** `host:port`. */
    override fun toString(): String = "$host:$port"
}

/** How long HTTP/3 leads HTTP/1.1 or HTTP/2 in a race on a network where QUIC was confirmed (RFC 8305 section 5). */
@ExperimentalKuicksilverApi
public sealed class RaceHeadStart {
    /** 1.5 x the host's smoothed RTT, or 250 ms without history, clamped to 100 ms..2 s. The default. */
    public object Adaptive : RaceHeadStart() {
        override fun toString(): String = "Adaptive"
    }

    /**
     * A fixed head start of [delay], 10 ms..2 s (RFC 8305 section 5); another value, `Duration.INFINITE` included (that is
     * [NoRace]), fails the engine's creation with IllegalArgumentException. On a network where QUIC was never confirmed the
     * head start is 10 ms, whatever this says.
     */
    public class Fixed(
        public val delay: Duration,
    ) : RaceHeadStart() {
        override fun equals(other: Any?): Boolean = other is Fixed && other.delay == delay

        override fun hashCode(): Int = delay.hashCode()

        override fun toString(): String = "Fixed($delay)"
    }

    /** No race: TCP only after HTTP/3 failed, on every network. */
    public object NoRace : RaceHeadStart() {
        override fun toString(): String = "NoRace"
    }
}

/** What `HttpClient.webTransport` does when a proxy applies to the URL (WebTransport runs over UDP, which an HTTP proxy does not carry). */
@ExperimentalKuicksilverApi
public enum class WebTransportProxyPolicy {
    /** The call fails with UnsupportedOperationException under any proxy. The default. */
    Refuse,

    /** Connects directly when an HTTP or SOCKS proxy applies; still refused under a CONNECT-UDP proxy. */
    BypassHttpProxy,

    /**
     * Connects directly when a CONNECT-UDP proxy applies, exposing the client's address to the origin, which the proxy
     * otherwise hides; still refused under an HTTP or SOCKS proxy.
     */
    BypassConnectUdpProxy,

    /** Connects directly under any proxy. */
    BypassAll,
}

/** Servers known to handle HTTP/1.1 (RFC 9112 section 6.1: "such knowledge might be in the form of specific user configuration"). */
@ExperimentalKuicksilverApi
public sealed class KnownServers {
    /** None: a chunked request to a server not seen yet goes after an `OPTIONS` probe. The default. */
    public object None : KnownServers() {
        override fun toString(): String = "None"
    }

    /** Every server. */
    public object All : KnownServers() {
        override fun toString(): String = "All"
    }

    /**
     * The [servers] listed: the host and port of the server the request goes to (the origin, or for plain `http` through
     * an HTTP proxy in absolute form, the proxy), compared as [HostPort] does.
     */
    public class Listed(
        servers: Set<HostPort>,
    ) : KnownServers() {
        /** The servers, as given. */
        public val servers: Set<HostPort> = servers.toSet()

        override fun equals(other: Any?): Boolean = other is Listed && other.servers == servers

        override fun hashCode(): Int = servers.hashCode()

        override fun toString(): String = "Listed($servers)"
    }

    internal fun knows(server: HostPort): Boolean =
        when (this) {
            None -> false
            All -> true
            is Listed -> server in servers
        }
}

/**
 * The TLS of the engine's connections, HTTP/3 and TCP alike (the fallback keeps the same trust and pins, threat-model 3.18),
 * and the base of the proxies' TLS ([ProxiesConfig.tls]). ALPN and the server name come from the request (`h3`, or `h2` and
 * `http/1.1`; the URL's host); verify another name with [TrustConfig.ExpectedName]. The handshake's deadline is the
 * engine's `connectTimeout`.
 */
@KuicksilverDsl
public class ClientTlsConfig {
    /** How the server is trusted; default [TrustConfig.Platform], the OS trust store. */
    @SecuritySensitive
    public var trust: TrustConfig = TrustConfig.Platform

    /** The client certificate, sent when a server asks for one (mTLS); default null. */
    @SecuritySensitive
    public var identity: TlsIdentity? = null

    /**
     * The TLS versions offered over TCP; default [TlsVersions.Tls13]. [TlsVersions.Tls12And13] keeps HTTP/2 on (see
     * [Http2ClientConfig]); QUIC is TLS 1.3 only.
     */
    @SecuritySensitive
    public var versions: TlsVersions = TlsVersions.Tls13

    /** The TLS 1.3 cipher suites in preference order; default [CipherSuites.Default]. */
    @SecuritySensitive
    public var cipherSuites: CipherSuites = CipherSuites.Default

    /** The key-exchange groups and the key shares sent; default [KeyExchangeGroups.Default] (see `TlsConfig.Builder.keyExchangeGroups`). */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var keyExchangeGroups: KeyExchangeGroups = KeyExchangeGroups.Default

    /** How the revocation status the server staples is treated; default [RevocationPolicy.StapledIfPresent]. */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var revocation: RevocationPolicy = RevocationPolicy.StapledIfPresent

    /** TLS certificate compression (RFC 8879); default true (see `TlsConfig.Builder.certificateCompression`). */
    public var certificateCompression: Boolean = true

    /**
     * Receives the handshake secrets as RFC 9850 key log lines; default null, and keep it null in production: anyone who
     * reads the sink can decrypt the traffic.
     */
    @DelicateKuicksilverApi
    @SecuritySensitive
    public var keylog: KeylogSink? = null

    /** Encrypted Client Hello (RFC 9849): configurations per host, GREASE, the HTTPS records' `ech`; experimental. */
    @ExperimentalKuicksilverApi
    public val ech: EchClientConfig = EchClientConfig()

    /** Sets the [ech] options: `tls { ech { configLists = mapOf("example.com" to list) } }`. */
    @ExperimentalKuicksilverApi
    public fun ech(block: EchClientConfig.() -> Unit) {
        ech.block()
    }

    /** Applies these settings (not ECH, which the connection decides) to [b]. */
    @OptIn(DelicateKuicksilverApi::class)
    internal fun applyTo(b: TlsConfig.Builder) {
        b.trust = trust
        b.identity = identity
        b.versions = versions
        b.cipherSuites = cipherSuites
        b.keyExchangeGroups = keyExchangeGroups
        b.revocation = revocation
        b.certificateCompression = certificateCompression
        b.keylog = keylog
    }

    /** A copy of these settings (ECH: the GREASE switch only). */
    @OptIn(DelicateKuicksilverApi::class)
    internal fun copy(): ClientTlsConfig =
        ClientTlsConfig().also {
            it.trust = trust
            it.identity = identity
            it.versions = versions
            it.cipherSuites = cipherSuites
            it.keyExchangeGroups = keyExchangeGroups
            it.revocation = revocation
            it.certificateCompression = certificateCompression
            it.keylog = keylog
            it.ech.grease = ech.grease
        }
}

/** 0-RTT of the engine's HTTP/3 connections (ADR-0015); experimental. */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class ClientEarlyDataConfig {
    /**
     * Resume HTTP/3 connections with 0-RTT (off by default): the engine keeps the servers' session tickets for its lifetime
     * and sends GET, HEAD and OPTIONS requests without a body before the handshake completes; every other request waits
     * for it, and a 425 Too Early is retried once. Early requests can be replayed by an attacker (RFC 9846 section 8): turn
     * this on only for servers whose safe methods are free of side effects.
     */
    @SecuritySensitive
    public var enabled: Boolean = false
}

/**
 * Stall detection on HTTP/3 connections the engine chose over TCP (docs/guide/ktor.md, "Stalled HTTP/3 connections"). While
 * a request runs on such a connection (`Auto`, `Preferred`, [Http3ClientConfig.hints]; not [Http3Discovery.H3Only], which
 * has no TCP to go to, nor WebSockets and WebTransport sessions), a path that stopped carrying packets — [probeTimeouts]
 * probe timeouts in a row unanswered (RFC 9002 section 6.2) and no packet from the server for [minSilence] — drains the
 * connection, marks the alternative broken (RFC 7838 section 2.4) and sends the request over TCP when it may be repeated
 * (an idempotent method, a body that can be sent again, no response yet: `FallbackReason.QuicStalled`); other work waits
 * up to [abandonAfter] for the path to come back, then fails with [QuicStalledException] instead of at the idle timeout.
 * Experimental.
 */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class StallConfig {
    /**
     * True by default. A quiet watched connection sends a PING now and then (RFC 9000 section 10.1.2; at most every half of
     * the idle timeout in force) so that a cut path shows; the PINGs also keep the connection open while a response is
     * outstanding (RFC 9114 section 5.1), and wake a mobile radio: turn this off for clients that hold long-lived responses
     * open for minutes on mobile networks. False waits for the QUIC idle timeout and sends no PING, as before 0.3.0. An
     * `Idempotency-Key` header (an Internet-Draft) does not make a POST repeatable.
     */
    public var enabled: Boolean = true

    /**
     * Probe timeouts in a row without an acknowledgement (RFC 9002 section 6.2) before a connection may count as stalled:
     * 3 by default (with the PTO doubling at each, about 7 PTOs of time), 1..10; another value fails the engine's creation
     * with IllegalArgumentException.
     */
    public var probeTimeouts: Int = 3

    /**
     * The least time without any packet from the server, counted from the first unanswered probe timeout, before a
     * connection counts as stalled: 2 s by default, 100 ms..60 s; another value fails the engine's creation with
     * IllegalArgumentException. Before the handshake completed (a request on a 0-RTT connection) it is the time without any
     * answer at all since the request started, and two probe timeouts must have passed too.
     */
    public var minSilence: Duration = 2.seconds

    /**
     * How long work that may not be repeated waits on a stalled connection for the path to come back (a handover between
     * radio networks, Wi-Fi roaming): 10 s by default, 100 ms..10 min; another value fails the engine's creation with
     * IllegalArgumentException. A stall drains the connection: requests that may be repeated go over TCP at once, a POST or
     * a response body being read goes on, finishes if any packet arrives meanwhile, and fails with [QuicStalledException]
     * once this passed without one (or earlier, at the QUIC idle timeout).
     */
    public var abandonAfter: Duration = 10.seconds
}

/** WebTransport sessions of the client (`HttpClient.webTransport`); experimental. */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class ClientWebTransportConfig {
    /**
     * WebTransport sessions open at once on this client, over all its connections (they share the pooled ones, up to
     * [maxSessionsPerConnection] a connection); one more fails at once with IllegalStateException, nothing waits. 64 by
     * default, at least 1 (draft-ietf-webtrans-http3-17 section 8: "a WebTransport client SHOULD limit the number of outgoing
     * sessions it will open").
     */
    public var maxSessions: Int = 64

    /**
     * WebTransport sessions on one connection when flow control is on (draft-ietf-webtrans-http3-17 section 5.1), 1..65535;
     * 4 by default: the client opens another connection instead of putting more on one.
     */
    public var maxSessionsPerConnection: Int = 4

    /** What a WebTransport call does when a proxy applies to its URL; [WebTransportProxyPolicy.Refuse] by default. */
    @SecuritySensitive
    public var proxyPolicy: WebTransportProxyPolicy = WebTransportProxyPolicy.Refuse
}

/** The HTTP/3 options few applications change; experimental. */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class Http3ClientExpert {
    /** The head start of HTTP/3 in a race with TCP on a network where QUIC was confirmed; [RaceHeadStart.Adaptive] by default. */
    public var raceHeadStart: RaceHeadStart = RaceHeadStart.Adaptive

    /**
     * Forget alternatives without `persist=1` when the network changes, as RFC 7838 section 2.2 says a client SHOULD; true by
     * default. False keeps them across networks. The network is `network { networkId }`, or the networks
     * `http3 { migration }` follows while that is not set. With `networkId` a change is also seen across restarts, against
     * the network the store's entries were learned on ([AltSvcStore.networkId]); with the followed networks a start counts as
     * a change ([Http3ConnectionMigration.networks]). Without either source the engine sees no change.
     */
    public var clearAltSvcOnNetworkChange: Boolean = true

    /** Length in bytes (4..20) of the connection IDs the engine's QUIC endpoints issue; 8 by default. */
    public var connectionIdLength: Int = 8

    /**
     * The single-threaded dispatcher of the engine's QUIC endpoint loops; null (the default) gives each its own one-thread
     * view of `Dispatchers.Default`.
     */
    public var dispatcher: CoroutineDispatcher? = null
}

/** HTTP/3 of the client engine: whether and when it is used, and the transport and SETTINGS of its connections. */
@KuicksilverDsl
public class Http3ClientConfig {
    /** HTTP/3 on (the default); false: every request goes over TCP (HTTP/2 or HTTP/1.1), as with no `Alt-Svc` ever learned. */
    public var enabled: Boolean = true

    /** When `https://` requests use HTTP/3; [Http3Discovery.Auto] (learn from `Alt-Svc`) by default. Proxied requests never do. */
    public var discovery: Http3Discovery = Http3Discovery.Auto

    /** Origins known to speak HTTP/3 (Cronet `addQuicHint`): HTTP/3 from their first request, as [Http3Discovery.Preferred]. */
    public var hints: Set<HostPort> = emptySet()

    /** Where `Alt-Svc` records live; in memory by default. `FileAltSvcStore` keeps them across restarts. */
    public var altSvcStore: AltSvcStore = InMemoryAltSvcStore()

    /**
     * A kill switch for HTTP/3 (docs/guide/ktor.md, "Turning HTTP/3 off remotely"), called once per `https://` request on
     * the call's coroutine before anything connects: it must be quick and must not block, such as reading an
     * `AtomicBoolean` or a `StateFlow.value` that your remote configuration updates. While it returns false, requests go over
     * TCP (`ProtocolReason.Http3Disabled`; HTTP/2 stays on), open HTTP/3 connections take no new requests (calls running on
     * them finish; idle ones close after `pool { idleTimeout }`, or at once with `HttpClient.closeHttp3Connections()`), and
     * `Alt-Svc` is still learned, so switching back needs no warm-up. With [Http3Discovery.H3Only] a request fails with
     * UnsupportedOperationException instead, before any connection: that mode never uses TCP, and so does
     * `HttpClient.webTransport` (WebTransport has no TCP fallback). A switch that throws an Exception counts as true
     * (HTTP/3 allowed), so a broken configuration cannot break traffic; the engine logs that once per 5 minutes at most.
     */
    public var allowed: () -> Boolean = { true }

    /**
     * Lets pooled HTTP/3 connections follow the device's network (connection migration, RFC 9000 section 9;
     * docs/guide/ktor.md, "Connection migration"): on a switch from Wi-Fi to the mobile network, a connection moves to a
     * socket bound to the new network over a validated path with a fresh connection ID, so a download over HTTP/3 carries
     * on. Null (the default) leaves every connection on the socket it was opened on. `Http3ConnectionMigration
     * .followDefaultNetwork(connectivity)` on Android and `Http3ConnectionMigration.followDefaultNetwork()` on iOS and macOS
     * follow the system's default network. While `network { networkId }` is not set, the networks the hook follows are the
     * engine's network: a change resets broken marks and drops non-persistent alternatives.
     */
    @ExperimentalKuicksilverApi
    public var migration: Http3ConnectionMigration? = null

    /** 0-RTT of the engine's HTTP/3 connections; experimental. */
    @ExperimentalKuicksilverApi
    public val earlyData: ClientEarlyDataConfig = ClientEarlyDataConfig()

    /** Sets the [earlyData] options. */
    @ExperimentalKuicksilverApi
    public fun earlyData(block: ClientEarlyDataConfig.() -> Unit) {
        earlyData.block()
    }

    /** Stall detection on HTTP/3 connections; experimental. */
    @ExperimentalKuicksilverApi
    public val stall: StallConfig = StallConfig()

    /** Sets the [stall] options. */
    @ExperimentalKuicksilverApi
    public fun stall(block: StallConfig.() -> Unit) {
        stall.block()
    }

    /** WebTransport sessions; experimental. */
    @ExperimentalKuicksilverApi
    public val webTransport: ClientWebTransportConfig = ClientWebTransportConfig()

    /** Sets the [webTransport] options. */
    @ExperimentalKuicksilverApi
    public fun webTransport(block: ClientWebTransportConfig.() -> Unit) {
        webTransport.block()
    }

    /** HTTP/3 options few applications change; experimental. */
    @ExperimentalKuicksilverApi
    public val expert: Http3ClientExpert = Http3ClientExpert()

    /** Sets the [expert] options. */
    @ExperimentalKuicksilverApi
    public fun expert(block: Http3ClientExpert.() -> Unit) {
        expert.block()
    }

    internal val quicBuilder: QuicConfig.Builder = QuicConfig.Builder()

    /**
     * The QUIC transport of HTTP/3 connections (`QuicConfig.Builder`). The engine sets what it derives: `handshakeTimeout`
     * (the engine's `connectTimeout`), and refuses an explicit `handshakeTimeout`, `expert { maxUniStreams }` (at least 3
     * for HTTP/3, RFC 9114 section 6.2), `expert { resetStreamAt }` (on for WebTransport) and `expert { cancelErrorCode }`
     * (HTTP/3's H3_REQUEST_CANCELLED) with IllegalArgumentException when it is created.
     */
    public fun quic(block: QuicConfig.Builder.() -> Unit) {
        quicBuilder.block()
    }

    internal val settingsBuilder: Http3Settings.Builder = Http3Settings.Builder()

    /**
     * The HTTP/3 SETTINGS and limits of the engine's connections (`Http3Settings.Builder`: QPACK, field sections). The
     * engine derives `enableConnectProtocol`, `h3Datagram` and `webTransport { enabled, maxSessions }` (from [webTransport])
     * and refuses them here, as it does `earlyData` (a server's policy); the per-session WebTransport flow-control limits
     * (`webTransport { initialMaxStreamsBidi, initialMaxStreamsUni, initialMaxData }`) are the client's to set here.
     */
    public fun settings(block: Http3Settings.Builder.() -> Unit) {
        settingsBuilder.block()
    }
}

/**
 * HTTP/2 on the TCP path (RFC 9113; docs/guide/ktor.md, "HTTP/2"): every `https://` connection over TCP offers `h2` and
 * `http/1.1` in ALPN, and a server that picks `h2` gets one multiplexed connection per route instead of up to
 * `pool { maxConnectionsPerRoute }` HTTP/1.1 connections. An `http://` request uses HTTP/1.1, unless its origin is listed in
 * [priorKnowledge] (h2c). A `wss://` WebSocket goes over HTTP/2 (RFC 8441, Extended CONNECT) on a connection to its origin
 * that is there already and whose server allows it; otherwise it opens a connection of its own that offers `http/1.1` only
 * (docs/guide/ktor.md, "WebSockets over HTTP/2"). HTTP/3 is unaffected, and so is its kill switch. A `tls` block that allows
 * TLS 1.2 offers `h2` as well (RFC 9113 section 9.2): over TLS 1.2 renegotiation stays refused, and a server that asks for
 * one ends the connection with a connection error of type PROTOCOL_ERROR (section 9.2.1); the TLS 1.2 suites are ECDHE with
 * an AEAD only, none of them prohibited by section 9.2.2.
 */
@KuicksilverDsl
public class Http2ClientConfig {
    /**
     * Offer HTTP/2 (true by default). False offers only `http/1.1` in ALPN, as before 0.3.0: the switch for a server or
     * middlebox whose HTTP/2 is broken.
     */
    public var enabled: Boolean = true

    /**
     * Sends a PING this often on every HTTP/2 connection and closes the connection when one is still unanswered at the
     * next (OkHttp's `pingInterval`); its calls fail. Null (the default) sends none. At least 100 ms.
     */
    public var pingInterval: Duration? = null

    /**
     * The `http://` origins (host and port, as in request URLs) whose server is known to speak HTTP/2 over cleartext TCP:
     * their requests go over h2c with prior knowledge (RFC 9113 section 3.3), the client connection preface right after
     * the TCP connect, without TLS, without ALPN and without `Upgrade: h2c` (deprecated by section 3.1, never sent). Empty
     * by default. h2c is cleartext (CWE-319), so name only servers on a trusted network or behind a sidecar that protects
     * the hop (docs/guide/ktor.md, "h2c"). No fallback: a listed server that does not speak h2c fails the call with the
     * connection error; only a server that ends the connection with HTTP_1_1_REQUIRED gets HTTP/1.1 from then on. An
     * `https://` URL never uses this. A `ws://` WebSocket to a listed origin goes as an Extended CONNECT (RFC 8441,
     * `:scheme http`) on the origin's h2c connection. On Android the app's cleartext policy applies as to any `http://`
     * request. Ignored when [enabled] is false.
     */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var priorKnowledge: Set<HostPort> = emptySet()

    internal val settingsBuilder: Http2Settings.Builder = Http2Settings.Builder()

    /**
     * Our side of each HTTP/2 connection (`Http2Settings.Builder`): windows, SETTINGS and the limits held against the server
     * (threat model 3.23). Its `maxConcurrentStreams` is what we allow the server to open towards us, which a client never
     * uses: a server's limit for our requests comes from its own SETTINGS.
     */
    @ExperimentalKuicksilverApi
    public fun settings(block: Http2Settings.Builder.() -> Unit) {
        settingsBuilder.block()
    }
}

/** HTTP/1.1 of the client engine; experimental. */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class Http1ClientConfig {
    /**
     * Servers known to handle HTTP/1.1 (RFC 9112 section 6.1): a request with Transfer-Encoding (a body of unknown length,
     * or a transfer coding the application applied) goes to them chunked at once, without the `OPTIONS` the engine
     * otherwise sends first to a server it has not seen answer with HTTP/1.1 nor pick ALPN `http/1.1`. [KnownServers.None]
     * by default.
     */
    public var knownServers: KnownServers = KnownServers.None
}

/** The engine's connection pool. */
@KuicksilverDsl
public class PoolConfig {
    /**
     * TCP connections (HTTP/1.1 and HTTP/2) open at once across all routes, idle ones included (CIO's
     * `maxConnectionsCount`, the same default 1000). A request beyond it waits, in FIFO order, within the connect timeout;
     * when other routes hold idle connections, the oldest one is closed to make room instead. HTTP/3 multiplexes and is
     * limited per origin instead.
     */
    public var maxConnections: Int = 1000

    /**
     * TCP connections (HTTP/1.1 and HTTP/2) open at once to one route (scheme, host, port and proxy), idle ones included
     * (CIO's `endpoint.maxConnectionsPerRoute`, the same default 100); further requests to it wait in FIFO order within the
     * connect timeout, failing with `ConnectTimeoutException` when no connection frees up in time. An HTTP/2 connection counts
     * once, however many requests it carries; a second one opens only when the first has no stream left under the server's
     * SETTINGS_MAX_CONCURRENT_STREAMS.
     */
    public var maxConnectionsPerRoute: Int = 100

    /**
     * Idle HTTP/1.1 keep-alive connections kept per route (origin and proxy) for reuse; it does not limit open connections,
     * [maxConnectionsPerRoute] and [maxConnections] do. 0 keeps none.
     */
    public var maxIdleConnectionsPerRoute: Int = 4

    /**
     * How long a connection without requests is kept: an idle HTTP/1.1 keep-alive connection, or an HTTP/2 or HTTP/3
     * connection with no request in flight (5 minutes, as OkHttp's keep-alive). For HTTP/3 the effective value is the
     * smaller of this and the QUIC `maxIdleTimeout` (30 s by default) unless `http3 { quic { keepAlive } }` is set. A
     * background task closes expired connections and drops the bookkeeping of origins without connections.
     */
    public var idleTimeout: Duration = 5.minutes

    /**
     * Age after which a connection takes no new requests: a pooled HTTP/1.1 connection is closed instead of reused, and new
     * HTTP/2 and HTTP/3 requests go to a new connection while the old one finishes its requests and then closes. Null (the
     * default): no limit, as in OkHttp and CIO; a finite value spreads load after DNS or load-balancer changes.
     */
    public var maxConnectionLifetime: Duration? = null

    /**
     * Connection coalescing (RFC 9113 section 9.1.1, RFC 9114 section 3.3; ADR-0018): a request for one `https` origin may
     * go on an open HTTP/2 or HTTP/3 connection of another origin when that connection's certificate passes, now, every
     * check a new connection to the request's host would make (the trust, pins and name, validity) and the host resolves to
     * the address and port the connection is connected to (RFC 9110 section 4.3.3), checked per request. A 421 (Misdirected
     * Request) to such a request is answered by sending it once more on a connection of its own origin (RFC 9110 section
     * 15.5.20), whatever its method; a streamed body already consumed fails the call with [H3BodyConsumed] instead. Never
     * through a proxy, never for a WebSocket or WebTransport, never over h2c, never under `TrustConfig.Tofu` or
     * `TrustConfig.ExpectedName`, and over HTTP/3 only where the request has an HTTP/3 endpoint of its own at the
     * connection's address. False (the default): every origin gets connections of its own; the one certificate then speaks
     * for the origins it covers, so turn it on only where the servers behind such a certificate answer 421 to the hosts they
     * do not serve (docs/guide/ktor.md, "Connection coalescing"). Turned on, every HTTP/2 connection that may carry other
     * origins sends `cookie` as a literal HPACK never indexes (RFC 7541 section 7.1).
     */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var coalescing: Boolean = false
}

/** Name resolution and connection racing of the client engine. */
@KuicksilverDsl
public class ClientNetworkConfig {
    /**
     * Resolves host names to the addresses the engine connects to, over TCP and QUIC, with Happy Eyeballs (RFC 8305) on what
     * it answers: [Dns.System] (the default) or your own, after OkHttp's `Dns`. Its lookup is part of connecting
     * (`connectTimeout` bounds it), it never gets address literals, it is asked for an HTTP proxy's name but never for the
     * origin's behind it, and its answers never stand in for the host name in TLS. See [Dns] and docs/guide/ktor.md,
     * "Name resolution".
     */
    @ExperimentalKuicksilverApi
    @SecuritySensitive
    public var dns: Dns = Dns.System

    /**
     * Where [Http3Discovery.Auto] looks up HTTPS resource records (RFC 9460; docs/guide/ktor.md, "HTTPS records"):
     * [HttpsRecordSource.Off] (the default), the system resolver ([HttpsRecordSource.System]) or your DNS-over-HTTPS exchange
     * ([HttpsRecordSource.Exchange]). An `https://` request to a host name asks for the origin's records, follows AliasMode
     * records, and connects to their endpoints in priority order over the transports each allows, then to the origin as
     * without records; the certificate is checked against the origin's name whatever the target. No lookup is made for
     * [Http3Discovery.Preferred], [Http3Discovery.H3Only], `http3 { hints }`, IP addresses, requests through a proxy, or while
     * `http3 { allowed }` says no. An `http://` request first asks for the records of its `https` URL and, when the origin
     * has any usable one, gets a `307` to that URL from the engine instead (RFC 9460 section 9.5). Answers are cached for their
     * TTL until the network changes, and only when the engine sees the network ([networkId] is set, or `http3 { migration }`
     * follows one; RFC 9460 section 12).
     */
    @ExperimentalKuicksilverApi
    public var httpsRecords: HttpsRecordSource = HttpsRecordSource.Off

    /**
     * How long a request waits for the HTTPS records after the origin's addresses resolved (50 ms by default, as Chromium):
     * an answer that comes later is cached for the next request. 50 ms (RFC 9460 section 5.1) to 1 s; any other value
     * fails the engine's creation with IllegalArgumentException. The connect timeout bounds the whole wait.
     */
    @ExperimentalKuicksilverApi
    public var httpsRecordWait: Duration = 50.milliseconds

    /**
     * Happy Eyeballs (RFC 8305) for the engine's connects, TCP and QUIC (docs/guide/ktor.md, "Happy Eyeballs"): the next
     * address is tried when this delay has passed since the last attempt started or as soon as an attempt failed, and the
     * first connection wins. 250 ms by default, as RFC 8305 section 8 recommends; 100 ms to 2 s, or null to try one address
     * after another. Any other value fails the engine's creation with IllegalArgumentException. `connectTimeout` bounds all
     * attempts together.
     */
    public var happyEyeballsDelay: Duration? = 250.milliseconds

    /**
     * Identifies the current network; a change resets "broken" marks, QUIC confirmation and the HTTPS record cache, and drops
     * alternatives without `persist=1` (`http3 { expert { clearAltSvcOnNetworkChange } }`). Null (the default): not set; the
     * networks `http3 { migration }` follows ([Http3ConnectionMigration.networks]) are the network then, when it has them;
     * without either, the engine sees no network change and keeps no HTTPS records of its own (RFC 9460 section 12).
     */
    public var networkId: (() -> String?)? = null
}

/** Proxies of the client engine; Ktor's `proxy` (on the engine configuration) names an explicit one. Experimental. */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class ProxiesConfig {
    /**
     * Where the proxy for a request comes from when `proxy` is not set (an explicit `proxy` always wins):
     * [ProxyResolvers.System] (the default: the platform's proxy settings), [ProxyResolvers.Environment] (`https_proxy`,
     * `no_proxy`...), [ProxyResolvers.None] for direct connections, or your own [ProxyResolver]. A request through a proxy
     * uses TCP only (HTTP/1.1, or HTTP/2 with the origin inside a tunnel) and neither uses nor learns `Alt-Svc`; `localhost`
     * and loopback addresses always connect directly with the built-in resolvers. docs/guide/ktor.md, "Proxies".
     */
    @SecuritySensitive
    public var resolver: ProxyResolver = ProxyResolvers.System

    /**
     * Credentials for the explicit `proxy` only: a proxy [resolver] returns carries its own ([ResolvedProxy.credentials]).
     * SOCKS5 username/password (RFC 1929), or `Proxy-Authorization: Basic` on an HTTP proxy's CONNECT and absolute-form
     * requests, sent with the first request unless the request sets its own `Proxy-Authorization`. Null (the default) for
     * none. Both go in clear to an `http://` or SOCKS5 proxy and only inside TLS to an `https://` one, never to the origin,
     * and never into the engine's logs or events. A SOCKS5 `proxy` with an empty password, or an HTTP `proxy` with a user
     * name that contains a colon or control characters, fails the engine's creation with IllegalArgumentException.
     */
    @SecuritySensitive
    public var credentials: ProxyCredentials? = null

    internal var tlsBlock: (ClientTlsConfig.() -> Unit)? = null

    /**
     * The TLS of connections to an `https://` proxy ([ResolvedProxy.https]) and of the QUIC connections to a [connectUdp]
     * proxy. Without this block they take the engine's `tls { }` with its trust minus what names the origin (an
     * `ExpectedName` gives way to its base, a `Pinned` to its base) and no client certificate. The block starts from that
     * same trust and no identity and may set anything. The server name (SNI and the name verified) is the proxy's host and
     * ALPN offers `http/1.1` only (`h3` to a CONNECT-UDP proxy). An ECH configuration set here is offered to the proxy as
     * given. docs/guide/ktor.md, "Proxies".
     */
    @SecuritySensitive
    public fun tls(block: ClientTlsConfig.() -> Unit) {
        tlsBlock = block
    }

    /**
     * A CONNECT-UDP proxy (RFC 9298, MASQUE) for HTTP/3, or null (the default) for none. An `https` request it applies to
     * goes over HTTP/3 inside a UDP tunnel through it, whatever `proxy` or [resolver] say: never over TCP and never directly.
     * Such a request fails, with the reason, when the origin has no HTTP/3, when the proxy refuses the tunnel, with
     * `http3 { enabled = false }` or while `http3 { allowed }` says no. docs/guide/ktor.md, "HTTP/3 through a CONNECT-UDP proxy".
     */
    @SecuritySensitive
    public var connectUdp: ConnectUdpProxy? = null

    /**
     * Whether a proxy auto-configuration (PAC) script the system settings name gets a `wss://` WebSocket's whole URI with
     * its resource name, as RFC 6455 section 4.1 asks, on Apple platforms and Windows ([ProxyResolvers.System]). Off by
     * default: every script gets `wss://host[:port]/` only, as browsers give `https` and `wss` URLs to PAC scripts, since a
     * script can send what it is given out through `dnsResolve` (CVE-2016-3763, CVE-2016-5134). A script found by WPAD or
     * fetched over plain `http://` never gets more, whatever this says. True only weakens the default.
     */
    @DelicateKuicksilverApi
    @SecuritySensitive
    public var pacFullWebSocketUrl: Boolean = false
}

/** WebSockets of the client engine. */
@KuicksilverDsl
public class ClientWebSocketsConfig {
    /**
     * The largest WebSocket message, and so frame, the client takes from a server, in bytes (RFC 6455 section 10.4); 16 MiB
     * by default. A frame whose header claims more, or that takes its message past it, closes the connection with 1009
     * (message too big) before any of its payload is read; a compressed message is held to the smaller of this and the
     * extension's limit, counted inflated. Over HTTP/1.1, HTTP/2 and HTTP/3 alike; Ktor's `WebSockets { maxFrameSize }`
     * applies on top of it. Less than 1 fails the engine's creation with IllegalArgumentException.
     */
    @SecuritySensitive
    public var maxMessageSize: Long = 16_777_216L
}

/** Where the engine's diagnostics, traces and events go. */
@KuicksilverDsl
public class ClientObservability {
    /**
     * Where the engine's diagnostics go, its QUIC endpoints' included (docs/guide/ktor.md, "Observability");
     * [KuicksilverLogger.Default] (the platform's logger, warnings and up) by default.
     */
    public var logger: KuicksilverLogger = KuicksilverLogger.Default

    /**
     * The level at which [logger] gets one line per answered call that HTTP/3 could have served but did not
     * (docs/guide/ktor.md, "Why did this request not use HTTP/3?"): a lost race, a fallback, a broken alternative, a proxy,
     * HTTP/3 turned off. [LogLevel.Info] by default, which the default logger (warnings and up) leaves out: use
     * `KuicksilverLogger.platform(LogLevel.Info)` to see them. Calls over HTTP/3, and calls HTTP/3 was never a candidate for,
     * are logged at [LogLevel.Debug]. Null writes no line. The line names the method, scheme, host, port and path, never the
     * query or the user info.
     */
    public var protocolChoiceLogLevel: LogLevel? = LogLevel.Info

    /**
     * A qlog trace per HTTP/3 connection (docs/guide/quic.md, "qlog"); null (the default) traces nothing. Wrap a file sink in
     * `AsyncQlogSink` so a slow disk never stalls the endpoint. After `HttpClient.close()`,
     * `client.engine.coroutineContext.job.join()` returns once every connection's trace was closed; then `flush()` an
     * `AsyncQlogSink` to have its writer finish.
     */
    public var qlog: QlogSink? = null

    /** Hears every call: protocol choice, race, fallback, Alt-Svc, connection pool and retries; null (the default) for none. */
    @ExperimentalKuicksilverApi
    public var eventListener: KuicksilverEventListener? = null

    /** Hears the lifecycle of every QUIC connection of the engine; null (the default) for none. */
    @ExperimentalKuicksilverApi
    public var connectionListener: ConnectionListener? = null
}

/**
 * Configuration of `HttpClient(Kuicksilver)`: [connectTimeout] at the top, everything else in blocks (docs/guide/configuration.md,
 * "Ktor client"). Ktor's own `proxy`, `pipelining` and `threadsCount` are inherited.
 */
public class KuicksilverEngineConfig : HttpClientEngineConfig() {
    /**
     * Connect timeout when `HttpTimeout` sets none (TCP + TLS, or the QUIC handshake; the name resolution and the wait for
     * a pool slot share it). A WebSocket over HTTP/1.1 is connecting until the server answers its opening handshake (RFC
     * 6455 section 4.1): that answer must arrive within the same timeout, else the WebSocket fails with
     * `ConnectTimeoutException`.
     */
    public var connectTimeout: Duration = 10.seconds

    /** TLS of the engine's connections; change it with [tls]. */
    public val tls: ClientTlsConfig = ClientTlsConfig()

    /** Configures [tls] in place: `engine { tls { trust = TrustConfig.AnchoredCa(listOf(ca)) } }`. */
    public fun tls(block: ClientTlsConfig.() -> Unit) {
        tls.block()
    }

    /** HTTP/3 discovery, racing and connection settings; change it with [http3]. */
    public val http3: Http3ClientConfig = Http3ClientConfig()

    /** Configures [http3] in place: `engine { http3 { hints = setOf(HostPort("api.example.com", 443)) } }`. */
    public fun http3(block: Http3ClientConfig.() -> Unit) {
        http3.block()
    }

    /** HTTP/2 on the TCP path; change it with [http2]. */
    public val http2: Http2ClientConfig = Http2ClientConfig()

    /** Configures [http2] in place: `engine { http2 { enabled = false } }`. */
    public fun http2(block: Http2ClientConfig.() -> Unit) {
        http2.block()
    }

    /** HTTP/1.1 options; experimental. */
    @ExperimentalKuicksilverApi
    public val http1: Http1ClientConfig = Http1ClientConfig()

    /** Configures [http1] in place. */
    @ExperimentalKuicksilverApi
    public fun http1(block: Http1ClientConfig.() -> Unit) {
        http1.block()
    }

    /** The connection pool; change it with [pool]. */
    public val pool: PoolConfig = PoolConfig()

    /** Configures [pool] in place: `engine { pool { idleTimeout = 1.minutes } }`. */
    public fun pool(block: PoolConfig.() -> Unit) {
        pool.block()
    }

    /** Name resolution and racing; change it with [network]. */
    public val network: ClientNetworkConfig = ClientNetworkConfig()

    /** Configures [network] in place. */
    public fun network(block: ClientNetworkConfig.() -> Unit) {
        network.block()
    }

    /** Proxies; experimental. */
    @ExperimentalKuicksilverApi
    public val proxies: ProxiesConfig = ProxiesConfig()

    /** Configures [proxies] in place. */
    @ExperimentalKuicksilverApi
    public fun proxies(block: ProxiesConfig.() -> Unit) {
        proxies.block()
    }

    /** WebSockets; change it with [webSockets]. */
    public val webSockets: ClientWebSocketsConfig = ClientWebSocketsConfig()

    /** Configures [webSockets] in place. */
    public fun webSockets(block: ClientWebSocketsConfig.() -> Unit) {
        webSockets.block()
    }

    /** Logs, traces and events; change it with [observability]. */
    public val observability: ClientObservability = ClientObservability()

    /** Configures [observability] in place: `engine { observability { logger = KuicksilverLogger.platform(LogLevel.Info) } }`. */
    public fun observability(block: ClientObservability.() -> Unit) {
        observability.block()
    }

    /** Replaces the system resolver for both pools (tests: names and addresses the test owns), both families at once. */
    internal var resolverForTest: (suspend (String, Int) -> List<io.kuicksilver.ktor.network.TcpAddress>)? = null

    /** Replaces the system resolver one family at a time (tests: AAAA and A answers that come when the test says). */
    internal var familyResolverForTest: (suspend (name: String, ipv6: Boolean) -> List<io.kuicksilver.ktor.network.TcpAddress>)? = null

    /** The NAT64 state for tests with a resolver of their own (default: never an IPv6-only network). */
    internal var nat64ForTest: Nat64? = null

    /** How the engine's QUIC endpoints open their sockets (tests: `MemoryNetwork`); null: the platform's. */
    internal var endpointIoForTest: (suspend (io.ktor.network.sockets.InetSocketAddress) -> io.kuicksilver.quic.DatagramIo)? = null

    /** The QUIC crypto provider of the engine's endpoints (tests); null: OpenSSL. */
    internal var cryptoForTest: io.kuicksilver.tls.QuicCrypto? = null

    /** A QUIC handshake deadline of its own (tests: a handshake that times out before the connect timeout); null: the connect timeout. */
    internal var quicHandshakeTimeoutForTest: Duration? = null

    /** The QUIC settings of HTTP/3 connections: the `http3 { quic { } }` block with what the engine derives. */
    internal fun resolveQuic(): QuicConfig {
        refuseDerived("http3 { quic { ", http3.quicBuilder.assignedOptions(), QUIC_DERIVED)
        // the handshake's deadline is the connect timeout (as each request's own connect timeout bounds it too)
        val handshake = quicHandshakeTimeoutForTest ?: connectTimeout
        val built = http3.quicBuilder.build()
        return if (built.handshakeTimeout == handshake) built else built.toBuilder().apply { handshakeTimeout = handshake }.build()
    }

    /** The HTTP/3 SETTINGS of the engine's connections: the `http3 { settings { } }` block, its derived options refused. */
    internal fun resolveHttp3Settings(): Http3Settings {
        refuseDerived("http3 { settings { ", http3.settingsBuilder.assignedOptions(), H3_DERIVED)
        return http3.settingsBuilder.build()
    }

    /** The HTTP/2 settings of the engine's connections. */
    internal fun resolveHttp2Settings(): Http2Settings = http2.settingsBuilder.build()

    internal companion object {
        /** The QUIC options the engine derives, and why (the refusal names both). */
        val QUIC_DERIVED: Map<String, String> =
            mapOf(
                "handshakeTimeout" to "the engine's connectTimeout",
                "expert.maxUniStreams" to "RFC 9114 section 6.2: HTTP/3 needs at least 3, the engine keeps the default",
                "expert.resetStreamAt" to "on for WebTransport (draft-ietf-webtrans-http3-17 section 3.1)",
                "expert.cancelErrorCode" to "HTTP/3 resets with its own codes (RFC 9114 section 8.1)",
            )

        /** The HTTP/3 SETTINGS the client engine derives. */
        val H3_DERIVED: Map<String, String> =
            mapOf(
                "enableConnectProtocol" to "on for WebSockets and WebTransport (RFC 9220)",
                "h3Datagram" to "follows the QUIC datagrams (RFC 9297)",
                "webTransport" to
                    "enabled is on for each webTransport() call; maxSessions is http3 { webTransport { maxSessionsPerConnection } }",
                "earlyData" to "a server's policy; the client's 0-RTT is http3 { earlyData { enabled } }",
            )

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
