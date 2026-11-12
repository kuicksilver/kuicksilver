// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.HttpClientEngineConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/** How the engine finds and uses HTTP/3 (after JDK 26 `Http3DiscoveryMode` and Cronet's QUIC hints). */
public enum class Http3DiscoveryMode {
    /** HTTP/1.1 first; HTTP/3 once the origin advertised it with `Alt-Svc` (RFC 7838). The default. */
    Auto,

    /** HTTP/3 by prior knowledge, falling back to HTTP/1.1 (like `curl --http3`). */
    Preferred,

    /** HTTP/3 only, no fallback (like `curl --http3-only`). */
    H3Only,

    /**
     * No HTTP/3: TCP only, that is HTTP/1.1, or HTTP/2 when the server offers it over TLS ([KuicksilverEngineConfig.http2]).
     * The name predates HTTP/2 support (0.3.0).
     */
    H1Only,
}

/**
 * A host and port, for [Http3ClientConfig.quicHints].
 *
 * @property host the host exactly as in request URLs (compared as is, no case folding or resolution).
 * @property port the port of the `https` origin, 443 for URLs without one.
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

/** HTTP/3 settings of the client engine. */
@KuicksilverDsl
public class Http3ClientConfig {
    /** When `https://` requests use HTTP/3; [Http3DiscoveryMode.Auto] (learn from `Alt-Svc`) by default. Proxied requests never do. */
    public var discovery: Http3DiscoveryMode = Http3DiscoveryMode.Auto

    /** Origins known to speak HTTP/3 (Cronet `addQuicHint`): treated as [Http3DiscoveryMode.Preferred] in Auto mode. */
    public var quicHints: Set<HostPort> = emptySet()

    /** Where Alt-Svc records live; in memory by default. */
    public var altSvcStore: AltSvcStore = InMemoryAltSvcStore()

    /**
     * Where [Http3DiscoveryMode.Auto] looks up HTTPS resource records (RFC 9460; docs/guide/ktor.md, "HTTPS records"):
     * [HttpsRecordSource.Off] (the default), the system resolver ([HttpsRecordSource.System]) or your DNS-over-HTTPS
     * exchange ([HttpsRecordSource.Exchange]). An `https://` request to a host name asks for the origin's records (the
     * name for port 443, `_<port>._https.<name>` otherwise), follows AliasMode records, and connects to their endpoints in
     * priority order over the transports each allows (HTTP/3 and TCP racing for `alpn=h3`, TCP to the record's target and
     * `port`), then to the origin as without records; the certificate is checked against the origin's name whatever the
     * target. The address hints are not used, nor is `ech` (a record that requires it is skipped). A cached `Alt-Svc`
     * alternative is tried first. No lookup is made for [Http3DiscoveryMode.Preferred],
     * [Http3DiscoveryMode.H3Only], [quicHints], IP addresses, requests through a proxy, or while [http3Allowed] says no.
     * An `http://` request (in every discovery mode) first asks for the records of its `https` URL and, when the origin has
     * any usable one, gets a `307` to that URL from the engine instead (RFC 9460 section 9.5). Answers are cached for their TTL (at most
     * 1 day; "no records" for the SOA's negative TTL, not at all without one; at most 1000 names) until the network changes, and only when the engine sees
     * the network: [networkId] is set, or [connectionMigration] follows one (RFC 9460 section 12); a failed lookup is not cached.
     */
    @ExperimentalKuicksilverApi
    public var httpsRecords: HttpsRecordSource = HttpsRecordSource.Off

    /**
     * How long a request waits for the HTTPS records after the origin's addresses resolved (50 ms by default, as Chromium):
     * an answer that comes later is cached for the next request, and this one goes on without records. 50 ms (RFC 9460
     * section 5.1: an optimistic connection SHOULD wait that long) to 1 s;
     * any other value fails the engine's creation with [IllegalArgumentException]. The connect timeout bounds the whole wait.
     */
    @ExperimentalKuicksilverApi
    public var httpsRecordExtraWait: Duration = 50.milliseconds

    /**
     * Forget alternatives without `persist=1` when the network changes, as RFC 7838 section 2.2 says a client SHOULD; true by
     * default (before 0.2.1, false). False keeps them across networks. The network is [networkId], or the networks
     * [connectionMigration] follows while [networkId] is not set. With [networkId] a change is also seen across restarts,
     * against the network the store's entries were learned on ([AltSvcStore.networkId]); with the followed networks a start
     * counts as a change ([Http3ConnectionMigration.networks]). Without either source the engine sees no change.
     */
    public var clearOnNetworkChange: Boolean = true

    /**
     * Head start of HTTP/3 over HTTP/1.1 on a network where QUIC was confirmed; null: 1.5 x the host's smoothed RTT, or
     * 250 ms without history, clamped to 100 ms..2 s. An explicit value must be 10 ms..2 s (RFC 8305 section 5), or
     * [Duration.INFINITE] for HTTP/1.1 only after HTTP/3 failed, on every network; another one fails the engine's creation
     * with [IllegalArgumentException]. On a network where QUIC was never confirmed the head start is 10 ms, whatever
     * finite value is set.
     */
    public var hardDelay: Duration? = null

    /**
     * Identifies the current network; a change resets "broken" marks, QUIC confirmation and the HTTPS record cache, and drops
     * alternatives without `persist=1` ([clearOnNetworkChange]). null: one network. While it is not set, the networks
     * [connectionMigration] follows ([Http3ConnectionMigration.networks]) are the network, when it has them (the
     * `followDefaultNetwork` factories do); without either, the engine sees no network change and keeps no HTTPS records of
     * its own ([httpsRecords]): RFC 9460 section 12 requires that cache to be flushed on network changes.
     */
    public var networkId: () -> String? = { null }
        set(value) {
            field = value
            networkIdSet = true
        }

    /** Whether [networkId] was set (the HTTPS record cache needs it, RFC 9460 section 12). */
    internal var networkIdSet: Boolean = false

    /** HTTP/3 settings of the engine's connections. */
    public var settings: Http3Settings = Http3Settings.Default

    /**
     * The client QUIC endpoint (dispatcher, crypto provider, socket factory). Its `connectionIdLength` and the one of
     * [KuicksilverEngineConfig.quic] are kept equal: the one left at its default follows the other, and two different explicit
     * values fail the engine's creation with [IllegalArgumentException].
     */
    public var endpoint: QuicEndpointConfig = QuicEndpointConfig.Default

    /**
     * Resume HTTP/3 connections with 0-RTT (off by default; ADR-0015): the engine keeps the servers' session tickets for
     * its lifetime and sends GET, HEAD and OPTIONS requests without a body before the handshake completes; every other
     * request waits for it, and a 425 Too Early is retried once. Early requests can be replayed by an attacker
     * (RFC 9846 section 8): turn this on only for servers whose safe methods are free of side effects.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var earlyData: Boolean = false

    /**
     * A qlog trace per HTTP/3 connection (docs/guide/quic.md, "qlog"), added to [KuicksilverEngineConfig.quic]; null (the
     * default) keeps that configuration's own. Wrap a file sink in `AsyncQlogSink` so a slow disk never stalls the endpoint:
     * `qlog = AsyncQlogSink(DirectoryQlogSink(dir))`.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var qlog: QlogSink? = null

    /** Hears the lifecycle of every QUIC connection of the engine (`QuicEndpointConfig.listener`); null keeps [endpoint]'s. */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var connectionListener: ConnectionListener? = null

    /**
     * `HttpClient.webTransport` connects directly even when a proxy applies to the URL; false by default, so such a call
     * fails with UnsupportedOperationException (WebTransport runs over UDP, which an HTTP proxy does not carry). Turn it on
     * only when a direct path to those servers is wanted despite the proxy.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var webTransportIgnoresProxy: Boolean = false

    /**
     * WebTransport sessions (`HttpClient.webTransport`) open at once on this client, each on a QUIC connection of its own;
     * one more fails at once with IllegalStateException, nothing waits. 64 by default, at least 1.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var maxWebTransportSessions: Int = 64

    /**
     * The level at which the engine's `logger` gets one line per answered call that HTTP/3 could have served but did not
     * (docs/guide/ktor.md, "Why did this request not use HTTP/3?"): a lost race, a fallback, a broken alternative, a proxy,
     * HTTP/3 turned off. [LogLevel.Info] by default, which the default logger (warnings and up) leaves out; calls over
     * HTTP/3, and calls HTTP/3 was never a candidate for (`http://`, `H1Only`, `Auto` without `Alt-Svc`), are logged at
     * [LogLevel.Debug]. Null writes no line. The line names the method, scheme, host, port and path, never the query
     * or the user info: `kuicksilver: GET https://example.com/ -> HTTP/1.1 (fallback=HandshakeTimeout, alt=example.com:443
     * via AltSvc, raced, headStart=10ms, h3Failure=Timeout, marked broken)`.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var diagnosticsLogLevel: LogLevel? = LogLevel.Info

    /**
     * A kill switch for HTTP/3 (docs/guide/ktor.md, "Turning HTTP/3 off remotely"), called once per `https://` request
     * (not with [Http3DiscoveryMode.H1Only]) on the call's coroutine before anything connects: it must be quick and must not
     * block, such as reading an `AtomicBoolean` or a `StateFlow.value` that your remote configuration updates. While it
     * returns false, requests go over TCP as with `H1Only` (`ProtocolReason.Http3Disabled`; HTTP/2 stays on: this switch is
     * HTTP/3's only, `http2 { enabled }` is HTTP/2's), open HTTP/3 connections
     * take no new requests (calls running on them finish; idle ones close after `idleTimeout`, or at once with
     * `HttpClient.closeHttp3Connections()`), and `Alt-Svc` is still learned, so switching back needs no warm-up. With
     * [Http3DiscoveryMode.H3Only] a request fails with UnsupportedOperationException instead, before any connection:
     * that mode never uses TCP, and so does `HttpClient.webTransport` (WebTransport has no TCP fallback). A switch that
     * throws an Exception counts as true (HTTP/3 allowed), so a broken configuration cannot break traffic; the engine logs
     * that once per 5 minutes at most. `HttpClient.closeHttp3Connections()` also drains open WebTransport sessions.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var http3Allowed: () -> Boolean = { true }

    /**
     * Lets pooled HTTP/3 connections follow the device's network (connection migration, RFC 9000 section 9; docs/guide/ktor.md,
     * "Connection migration"): on a switch from Wi-Fi to the mobile network, a connection moves to a socket bound to the new
     * network over a validated path with a fresh connection ID, so a download over HTTP/3 carries on. Null (the default)
     * leaves every connection on the socket it was opened on, as in 0.2: it survives only if the system routes that unbound
     * socket over the new network and the server takes it as a NAT rebinding, and may die at its idle timeout otherwise.
     * `Http3ConnectionMigration.followDefaultNetwork(connectivity)` on Android and `Http3ConnectionMigration.followDefaultNetwork()`
     * on iOS and macOS follow the system's default network; see [Http3ConnectionMigration] for other platforms and the rules.
     * While [networkId] is not set, the networks the hook follows ([Http3ConnectionMigration.networks]) are the engine's
     * network: a change resets broken marks and drops non-persistent alternatives as a [networkId] change does.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var connectionMigration: Http3ConnectionMigration? = null
}

/**
 * HTTP/2 on the TCP path (RFC 9113; docs/guide/ktor.md, "HTTP/2"): every `https://` connection over TCP offers `h2` and
 * `http/1.1` in ALPN, and a server that picks `h2` gets one multiplexed connection per route instead of up to
 * `maxConnectionsPerRoute` HTTP/1.1 connections. Never for `http://` (no cleartext HTTP/2, h2c). A `wss://` WebSocket goes
 * over HTTP/2 (RFC 8441, Extended CONNECT) on a connection to its origin that is there already and whose server allows it
 * (SETTINGS_ENABLE_CONNECT_PROTOCOL); otherwise it opens a connection of its own that offers `http/1.1` only, as in 0.2
 * (docs/guide/ktor.md, "WebSockets over HTTP/2"). HTTP/3 is unaffected, and so is its kill switch
 * (`http3 { http3Allowed }` turns HTTP/3 off, not HTTP/2). A `tls` block that allows TLS 1.2 (`versions =
 * TlsVersions.Tls12And13`) offers `h2` as well (RFC 9113 section 9.2): over TLS 1.2 renegotiation stays refused, and a server
 * that asks for one (a HelloRequest) ends the connection with a connection error of type PROTOCOL_ERROR (section 9.2.1);
 * the TLS 1.2 suites are ECDHE with an AEAD only, none of them prohibited by section 9.2.2.
 */
@ExperimentalKuicksilverApi
@KuicksilverDsl
public class Http2ClientConfig {
    /**
     * Offer HTTP/2 (true by default). False offers only `http/1.1` in ALPN, as before 0.3.0: the switch for a server or
     * middlebox whose HTTP/2 is broken.
     */
    public var enabled: Boolean = true

    /**
     * Our side of each HTTP/2 connection: windows, SETTINGS and the limits held against the server (threat model 3.23).
     * Its `maxConcurrentStreams` is what we allow the server to open towards us, which a client never uses: a server's
     * limit for our requests comes from its own SETTINGS.
     */
    public var settings: Http2Settings = Http2Settings()

    /**
     * Sends a PING this often on every HTTP/2 connection and closes the connection when one is still unanswered at the
     * next (OkHttp's `pingInterval`); its calls fail. [Duration.INFINITE] (the default) sends none. At least 100 ms.
     */
    public var pingInterval: Duration = Duration.INFINITE
}

/** Configuration of `HttpClient(Kuicksilver)`. */
public class KuicksilverEngineConfig : HttpClientEngineConfig() {
    /** Server verification for both HTTP/3 and HTTP/1.1 (the fallback keeps the same pins and trust, threat-model 3.18). */
    public var trust: TrustConfig = TrustConfig.Platform

    /** Client certificate, when servers ask for one. */
    public var identity: TlsIdentity? = null

    /**
     * Further TLS settings, applied after [trust] and [identity] (so the block may replace them). ALPN and the server name
     * come from the request (`h3`, or `h2` and `http/1.1`; the URL's host) and are set after the block: values the block
     * gives them are not used. Verify another name with `TrustConfig.ExpectedName` instead. Allowing TLS 1.2 here
     * (`versions = TlsVersions.Tls12And13`) keeps HTTP/2 on: see [Http2ClientConfig].
     */
    public var tls: TlsConfig.Builder.() -> Unit = {}

    /**
     * QUIC transport settings of HTTP/3 connections. A `connectionIdLength` set here is used by the engine's endpoint too
     * ([Http3ClientConfig.endpoint]). `maxUniStreams` must be at least 3 (RFC 9114 section 6.2) unless the discovery mode is
     * `H1Only`: the engine refuses a smaller value with IllegalArgumentException when it is created.
     */
    public var quic: QuicConfig = QuicConfig.Default

    /**
     * Idle HTTP/1.1 keep-alive connections kept per route (origin and proxy) for reuse; it does not limit open
     * connections, [maxConnectionsPerRoute] and [maxConnectionsCount] do. 0 keeps none.
     */
    public var maxIdleConnectionsPerRoute: Int = 4

    /**
     * TCP connections (HTTP/1.1 and HTTP/2) open at once across all routes, idle ones included (CIO's `maxConnectionsCount`, the same
     * default 1000). A request beyond it waits, in FIFO order, within the connect timeout; when other routes hold idle
     * connections, the oldest one is closed to make room instead. HTTP/3 multiplexes and is limited per origin instead.
     */
    @ExperimentalKuicksilverApi
    public var maxConnectionsCount: Int = 1000

    /**
     * TCP connections (HTTP/1.1 and HTTP/2) open at once to one route (scheme, host, port and proxy), idle ones included
     * (CIO's `endpoint.maxConnectionsPerRoute`, the same default 100); further requests to it wait in FIFO order within the
     * connect timeout, failing with `ConnectTimeoutException` when no connection frees up in time. An HTTP/2 connection
     * counts once, however many requests it carries; a second one opens only when the first has no stream left under the
     * server's SETTINGS_MAX_CONCURRENT_STREAMS.
     */
    @ExperimentalKuicksilverApi
    public var maxConnectionsPerRoute: Int = 100

    /**
     * How long a connection without requests is kept: an idle HTTP/1.1 keep-alive connection, or an HTTP/2 or HTTP/3
     * connection with no request in flight (5 minutes, as OkHttp's keep-alive; QUIC's own idle timeout may end it earlier). A
     * background task closes expired connections and drops the bookkeeping of origins without connections.
     */
    @ExperimentalKuicksilverApi
    public var idleTimeout: Duration = 5.minutes

    /**
     * Age after which a connection takes no new requests: a pooled HTTP/1.1 connection is closed instead of reused, and
     * new HTTP/2 and HTTP/3 requests go to a new connection while the old one finishes its requests and then closes. Infinite by
     * default, as in OkHttp and CIO; a finite value spreads load after DNS or load-balancer changes.
     */
    @ExperimentalKuicksilverApi
    public var maxConnectionLifetime: Duration = Duration.INFINITE

    /**
     * Connect timeout when `HttpTimeout` sets none (TCP + TLS, or the QUIC handshake; the name resolution and the wait for
     * a pool slot share it). A WebSocket over HTTP/1.1 is connecting until the server answers its opening handshake (RFC
     * 6455 section 4.1): that answer must arrive within the same timeout, counted from the moment the WebSocket has its
     * connection, else the WebSocket fails with `ConnectTimeoutException`. Its wait for another WebSocket to the same
     * address to finish connecting counts against neither.
     */
    public var connectTimeout: Duration = 10.seconds

    /**
     * Happy Eyeballs (RFC 8305) for the engine's connects, TCP and QUIC (docs/guide/ktor.md, "Happy Eyeballs"): a host
     * name's IPv6 and IPv4 addresses are asked for separately and raced as they arrive, sorted by RFC 6724 with the two
     * families alternating; the next address is tried when this delay has passed since the last attempt started or as soon
     * as an attempt failed (never within 10 ms of the last start), and the first connection wins (the others are cancelled
     * or closed). The same delay staggers HTTP/3's QUIC handshakes over the addresses. 250 ms by default, as RFC 8305
     * section 8 recommends; 100 ms (the Minimum Connection Attempt Delay) to 2 s (the Maximum) is allowed, or
     * [Duration.INFINITE] to try one address after another. Any other value fails the engine's creation with
     * [IllegalArgumentException]. [connectTimeout] bounds all attempts together.
     */
    @ExperimentalKuicksilverApi
    public var connectionAttemptDelay: Duration = 250.milliseconds

    /**
     * Credentials for the explicit `proxy` only: a proxy a [proxyResolver] returns carries its own
     * ([ResolvedProxy.credentials]: the user info of `https_proxy` and the like, or what your resolver gives
     * `ResolvedProxy.http(host, port, credentials)`), and these are never sent to it. SOCKS5 username/password (RFC 1929), offered to a SOCKS5 proxy and sent only
     * when it picks that method, or `Proxy-Authorization: Basic` on an HTTP proxy's CONNECT and absolute-form requests,
     * sent with the first request (no 407 round trip) unless the request sets its own `Proxy-Authorization`. Off the JVM
     * the proxy URL's user info (`http://user:password@proxy:3128`) wins over these. Null (the default) for none. Both go
     * in clear to the proxy (RFC 1929 section 5, RFC 7617 section 4), never to the origin, and never into the engine's
     * logs or events. A SOCKS5 `proxy` with an empty password (here or in its URL) fails the engine's creation with
     * [IllegalArgumentException]: RFC 1929 section 2 gives the password 1 to 255 octets (curl and Go send an empty one
     * anyway, outside the protocol).
     */
    @ExperimentalKuicksilverApi
    public var proxyCredentials: ProxyCredentials? = null

    /**
     * Where the proxy for a request comes from when `proxy` is not set (an explicit `proxy` always wins):
     * [ProxyResolvers.System] (the default: the platform's proxy settings), [ProxyResolvers.Environment]
     * (`https_proxy`, `no_proxy`...), [ProxyResolvers.None] for direct connections, or your own [ProxyResolver]. A
     * request through a proxy uses HTTP/1.1 only and neither uses nor learns `Alt-Svc`; `localhost` and loopback
     * addresses always connect directly with the built-in resolvers. docs/guide/ktor.md, "Proxies".
     */
    @ExperimentalKuicksilverApi
    public var proxyResolver: ProxyResolver = ProxyResolvers.System

    /**
     * The largest WebSocket message, and so frame, the client takes from a server, in bytes (RFC 6455 section 10.4: an
     * implementation "SHOULD impose a limit on frame sizes and the total message size after reassembly"); 16 MiB by
     * default, as `PerMessageDeflate`'s `maxInflatedMessageSize`. A frame whose header claims more, or that takes its
     * message past it, closes the connection with 1009 (message too big) before any of its payload is read; a compressed
     * message is held to the smaller of this and the extension's limit, counted inflated. Over HTTP/1.1, HTTP/2 and HTTP/3 alike;
     * Ktor's `WebSockets { maxFrameSize }` applies on top of it. Less than 1 fails the engine's creation with
     * [IllegalArgumentException].
     */
    @ExperimentalKuicksilverApi
    public var webSocketMaxMessageSize: Long = 16_777_216L // 16 MiB

    /** Replaces the system resolver for both pools (tests: names and addresses the test owns), both families at once. */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal var resolverForTest: (suspend (String, Int) -> List<io.kuicksilver.ktor.network.TcpAddress>)? = null

    /** Replaces the system resolver one family at a time (tests: AAAA and A answers that come when the test says). */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal var familyResolverForTest: (suspend (name: String, ipv6: Boolean) -> List<io.kuicksilver.ktor.network.TcpAddress>)? = null

    /** The NAT64 state for tests with a resolver of their own (default: never an IPv6-only network). */
    internal var nat64ForTest: Nat64? = null

    /** HTTP/3 discovery, racing and connection settings; change it with [http3]. */
    public val http3: Http3ClientConfig = Http3ClientConfig()

    /**
     * Where the engine's diagnostics go, its QUIC endpoint's included (docs/guide/ktor.md, "Observability"); null (the
     * default) keeps `http3.endpoint.logger`, which writes warnings to standard error.
     */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var logger: KuicksilverLogger? = null

    /** Hears every call: protocol choice, race, fallback, Alt-Svc, connection pool and retries; null (the default) for none. */
    @io.kuicksilver.annotations.ExperimentalKuicksilverApi
    public var eventListener: KuicksilverEventListener? = null

    /** HTTP/2 on the TCP path; change it with [http2]. */
    @ExperimentalKuicksilverApi
    public val http2: Http2ClientConfig = Http2ClientConfig()

    /** Configures [http2] in place: `engine { http2 { enabled = false } }`. */
    @ExperimentalKuicksilverApi
    public fun http2(block: Http2ClientConfig.() -> Unit) {
        http2.apply(block)
    }

    /** Configures [http3] in place: `engine { http3 { discovery = Http3DiscoveryMode.Preferred } }`. */
    public fun http3(block: Http3ClientConfig.() -> Unit) {
        http3.apply(block)
    }
}
