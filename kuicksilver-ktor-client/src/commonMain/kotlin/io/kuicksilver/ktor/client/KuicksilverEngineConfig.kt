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
 * A host and port, for [Http3ClientConfig.quicHints], [Http2ClientConfig.priorKnowledge] and [KuicksilverEngineConfig.http11Hints].
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
     * Stall detection on HTTP/3 connections the engine chose over TCP (docs/guide/ktor.md, "Stalled HTTP/3 connections"):
     * true by default. While a request runs on such a connection (`Auto`, `Preferred`, [quicHints]; not
     * [Http3DiscoveryMode.H3Only], which has no TCP to go to, nor WebSockets and WebTransport sessions), a path that stopped
     * carrying packets — [stallProbeTimeouts] probe timeouts in a row unanswered (RFC 9002 section 6.2) and no packet from the
     * server for [stallMinSilence] — drains the connection, marks the alternative broken (RFC 7838 section 2.4) and sends
     * the request over TCP when it may be repeated (an idempotent method, a body that can be sent again, no response yet:
     * `FallbackReason.QuicStalled`); other work waits up to [stallAbandonAfter] for the path to come back, then fails with
     * [QuicStalledException] instead of at the idle timeout. A quiet watched connection sends a PING now and then (RFC 9000
     * section 10.1.2; at most every half of the idle timeout in force) so that a cut path shows; the PINGs also keep the
     * connection open while a response is outstanding (RFC 9114 section 5.1), and wake a mobile radio: turn this off for
     * clients that hold long-lived responses open for minutes on mobile networks. False waits for the QUIC idle timeout and
     * sends no PING, as before 0.3.0. An `Idempotency-Key` header (an Internet-Draft) does not make a POST repeatable.
     */
    @ExperimentalKuicksilverApi
    public var stallDetection: Boolean = true

    /**
     * Probe timeouts in a row without an acknowledgement (RFC 9002 section 6.2) before a connection may count as stalled:
     * 3 by default (with the PTO doubling at each, about 7 PTOs of time), 1..10; another value fails the engine's creation
     * with [IllegalArgumentException]. See [stallDetection].
     */
    @ExperimentalKuicksilverApi
    public var stallProbeTimeouts: Int = 3

    /**
     * The least time without any packet from the server, counted from the first unanswered probe timeout, before a
     * connection counts as stalled: 2 s by default, 100 ms..60 s; another value fails the engine's creation with
     * [IllegalArgumentException]. Before the handshake completed (a request on a 0-RTT connection) it is the time without
     * any answer at all since the request started, and two probe timeouts must have passed too. See [stallDetection].
     */
    @ExperimentalKuicksilverApi
    public var stallMinSilence: Duration = 2.seconds

    /**
     * How long work that may not be repeated waits on a stalled connection for the path to come back (a handover between
     * radio networks, Wi-Fi roaming): 10 s by default, 100 ms..10 min; another value fails the engine's creation with
     * [IllegalArgumentException]. A stall drains the connection: requests that may be repeated go over TCP at once, a
     * POST or a response body being read goes on, finishes if any packet arrives meanwhile, and fails with
     * [QuicStalledException] once this passed without one (or earlier, at the QUIC idle timeout). See [stallDetection].
     */
    @ExperimentalKuicksilverApi
    public var stallAbandonAfter: Duration = 10.seconds

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
     * values fail the engine's creation with [IllegalArgumentException]. The engine binds it to the wildcard address
     * (`0.0.0.0:0`, dual-stack); connections to a loopback server leave from up to two more endpoints of this configuration,
     * one per family, bound to 127.0.0.1 (for 127.0.0.0/8 and its IPv4-mapped form) and ::1, each created at its first use,
     * so that no other local process holding that port on the loopback address gets the server's replies. The endpoints
     * share the engine's session tickets.
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
     * `qlog = AsyncQlogSink(DirectoryQlogSink(dir))`. After `HttpClient.close()`, `client.engine.coroutineContext.job.join()`
     * returns once every connection's trace was closed (docs/guide/ktor.md, "Closing the client"); then `flush()` an
     * `AsyncQlogSink` to have its writer finish.
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
     * WebTransport (`HttpClient.webTransport`) to a URL `connectUdpProxy` applies to connects directly instead of being
     * refused; false by default. WebTransport sessions do not go through the CONNECT-UDP tunnel, so this exposes the
     * client's address to the origin, which the proxy otherwise hides. Separate from [webTransportIgnoresProxy], which is
     * about HTTP and SOCKS proxies only.
     */
    @ExperimentalKuicksilverApi
    public var webTransportIgnoresConnectUdpProxy: Boolean = false

    /**
     * WebTransport sessions (`HttpClient.webTransport`) open at once on this client, over all its connections (they
     * share the pooled ones, up to `settings.webTransportMaxSessions` a connection); one more fails at once with
     * IllegalStateException, nothing waits. 64 by default, at least 1 (draft-ietf-webtrans-http3-17 section 8: "a
     * WebTransport client SHOULD limit the number of outgoing sessions it will open").
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
 * `maxConnectionsPerRoute` HTTP/1.1 connections. An `http://` request uses HTTP/1.1, unless its origin is listed in
 * [priorKnowledge] (h2c, HTTP/2 over cleartext TCP). A `wss://` WebSocket goes
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
    public var settings: Http2Settings = Http2Settings.Default

    /**
     * Sends a PING this often on every HTTP/2 connection and closes the connection when one is still unanswered at the
     * next (OkHttp's `pingInterval`); its calls fail. [Duration.INFINITE] (the default) sends none. At least 100 ms.
     */
    public var pingInterval: Duration = Duration.INFINITE

    /**
     * The `http://` origins (host and port, as in request URLs) whose server is known to speak HTTP/2 over cleartext TCP:
     * their requests go over h2c with prior knowledge (RFC 9113 section 3.3), the client connection preface right after
     * the TCP connect, without TLS, without ALPN and without `Upgrade: h2c` (deprecated by section 3.1, never sent). Empty
     * by default: every other `http://` request stays HTTP/1.1, and nothing is learned (a server that once spoke h2c is not
     * assumed to again, section 3.3). The list is per origin on purpose (OkHttp's `Protocol.H2_PRIOR_KNOWLEDGE` turns a
     * whole client to h2c): h2c is cleartext (CWE-319), so name only servers on a trusted network or behind a sidecar that
     * protects the hop, as a TLS-terminating proxy, a service mesh or a gRPC back end are (docs/guide/ktor.md, "h2c").
     *
     * No fallback: a listed server that does not speak h2c fails the call with the connection error (an HTTP/1.1-only
     * server's answer is no SETTINGS frame), and a TLS port fails its TLS handshake the same way; only a server that ends
     * the connection with HTTP_1_1_REQUIRED gets HTTP/1.1 from then on, as over TLS. An `https://` URL never uses this
     * (section 3.3: HTTP/2 over TLS "MUST use protocol negotiation in TLS"), nor HTTP/3 (an `http://` origin never learns
     * an alternative, `Alt-Svc` field or ALTSVC frame). Through an HTTP proxy the connection goes in a CONNECT tunnel
     * (absolute-form requests are HTTP/1.1; CONNECT to port 80, which many proxies refuse), through SOCKS5 as any other. A
     * `ws://` WebSocket to a listed origin goes as an Extended CONNECT (RFC 8441, `:scheme http`) on the origin's h2c
     * connection, which it opens itself when there is none (pooled, waiting for its SETTINGS at most 1 s); a server whose
     * SETTINGS do not allow Extended CONNECT gets an HTTP/1.1 Upgrade instead, on a connection of its own. On
     * Android the app's cleartext policy applies as to any `http://` request. Ignored when [enabled] is false.
     */
    public var priorKnowledge: Set<HostPort> = emptySet()
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
     * gives them are not used, nor are its `echConfigList` and `echGrease` (the connection's, from [ech]). Verify another name with `TrustConfig.ExpectedName` instead. Allowing TLS 1.2 here
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
     * Servers known to handle HTTP/1.1 (RFC 9112 section 6.1: "such knowledge might be in the form of specific user
     * configuration"): a request with Transfer-Encoding (a body of unknown length, or a transfer coding the application
     * applied) goes to them chunked at once, without the `OPTIONS` the engine otherwise sends first to a server it has not
     * seen answer with HTTP/1.1 nor pick ALPN `http/1.1`. The host and port of the server the request goes to: the origin,
     * or, for plain `http` through an HTTP proxy (absolute form), the proxy. Compared as [HostPort] does.
     */
    @ExperimentalKuicksilverApi
    public var http11Hints: Set<HostPort> = emptySet()

    /** Every server is known to handle HTTP/1.1, as [http11Hints] for all; false by default. */
    @ExperimentalKuicksilverApi
    public var assumeHttp11: Boolean = false

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
     * Connection coalescing (RFC 9113 section 9.1.1, RFC 9114 section 3.3; ADR-0018): a request for one `https` origin may go
     * on an open HTTP/2 or HTTP/3 connection of another origin when that connection's certificate passes, now, every check
     * a new connection to the request's host would make (the [trust], pins and name, validity) and the host resolves to the
     * address and port the connection is connected to (RFC 9110 section 4.3.3), checked per request. A 421 (Misdirected
     * Request) to such a request is answered by sending it once more on a connection of its own origin (RFC 9110 section
     * 15.5.20), whatever its method; a streamed body already consumed fails the call with [H3BodyConsumed] instead. Never
     * through a proxy, never for a WebSocket or WebTransport, never over h2c, never under `TrustConfig.Tofu` or
     * `TrustConfig.ExpectedName` (the certificate must name the host, RFC 9110 section 4.3.3), and over HTTP/3
     * only where the request has an HTTP/3 endpoint of its own (an `Alt-Svc` alternative, an HTTPS record, `Preferred`, a
     * hint) at the connection's address. False (the default): every origin gets connections of its own, as before 0.3.0; the
     * one certificate then speaks for the origins it covers, so turn it on only where the servers behind such a certificate
     * answer 421 to the hosts they do not serve (docs/guide/ktor.md, "Connection coalescing"). Turned on, every HTTP/2
     * connection that may carry other origins sends `cookie` as a literal HPACK never indexes (RFC 7541 section 7.1), which
     * costs the compression of cookies of 20 bytes or more on those connections.
     */
    @ExperimentalKuicksilverApi
    public var connectionCoalescing: Boolean = false

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
     * in clear to an `http://` or SOCKS5 proxy (RFC 1929 section 5, RFC 7617 section 4) and only inside TLS to an
     * `https://` one (after its certificate verified), never to the origin, and never into the engine's logs or events.
     * On the JVM and Android the `proxy` is a `java.net.Proxy`, which has no scheme: `ProxyBuilder.http(Url("https://..."))`
     * there makes an HTTP proxy on port 443, which the engine refuses (every request fails with
     * UnsupportedOperationException) rather than send the CONNECT and these credentials in clear to it; name an `https://`
     * proxy with a [proxyResolver] (`ResolvedProxy.https`) or the environment, and a plain proxy on port 443 with a
     * resolver's `ResolvedProxy.http`. A SOCKS5 `proxy` with an empty password (here or in its URL) fails the engine's creation with
     * [IllegalArgumentException]: RFC 1929 section 2 gives the password 1 to 255 octets (curl and Go send an empty one
     * anyway, outside the protocol). An HTTP `proxy` with a user name that contains a colon, or with control characters
     * in either part, fails the same way: RFC 7617 section 2 does not let `Basic` carry them.
     */
    @ExperimentalKuicksilverApi
    public var proxyCredentials: ProxyCredentials? = null

    /**
     * The TLS settings of connections to an `https://` proxy ([ResolvedProxy.https]: TLS to the proxy itself) and of the
     * QUIC connections to a [connectUdpProxy], separate from the origin's. Null (the default) takes the origin's: the [tls] block over [trust], then that trust without
     * what names the origin (a `TrustConfig.ExpectedName` gives way to its base, a `TrustConfig.Pinned` to its base: the
     * proxy has another name and another key), and no client certificate ([identity] is the origin's and is not shown to
     * the proxy). A block starts from that same trust and no identity and may set anything (`trust`, `identity` for a
     * proxy that wants a client certificate, `versions`...). Whatever it says, the server name, which is both SNI and
     * the name the certificate is verified against (RFC 9525), is the proxy's host and ALPN offers `http/1.1` only (`h3` to a CONNECT-UDP proxy); set
     * after the block. The origin's TLS inside the proxy's tunnel keeps [trust], [identity] and [tls], as without a
     * proxy. QUIC is TLS 1.3 only (RFC 9001 section 4.2): `versions` limited to TLS 1.2 here fails every handshake with a
     * CONNECT-UDP proxy. An ECH configuration (`echConfigList`) set here is offered to the proxy as given, and a rejection
     * fails the request without the retry of RFC 9849 section 6.1.6. docs/guide/ktor.md, "Proxies".
     */
    @ExperimentalKuicksilverApi
    public var proxyTls: (TlsConfig.Builder.() -> Unit)? = null

    /**
     * Where the proxy for a request comes from when `proxy` is not set (an explicit `proxy` always wins):
     * [ProxyResolvers.System] (the default: the platform's proxy settings), [ProxyResolvers.Environment]
     * (`https_proxy`, `no_proxy`...), [ProxyResolvers.None] for direct connections, or your own [ProxyResolver]. A
     * request through a proxy uses TCP only (HTTP/1.1, or HTTP/2 with the origin inside a tunnel) and neither uses nor
     * learns `Alt-Svc`; `localhost` and loopback
     * addresses always connect directly with the built-in resolvers. docs/guide/ktor.md, "Proxies".
     */
    @ExperimentalKuicksilverApi
    public var proxyResolver: ProxyResolver = ProxyResolvers.System

    /**
     * A CONNECT-UDP proxy (RFC 9298, MASQUE) for HTTP/3, or null (the default) for none. An `https` request it applies to
     * goes over HTTP/3 inside a UDP tunnel through it, whatever `proxy` or `proxyResolver` say (they keep deciding for the
     * requests it does not apply to): never over HTTP/1.1 or HTTP/2, and never directly, since either would leave the proxy
     * out. So such a request fails, with the reason, when the origin has no HTTP/3, when the proxy refuses the tunnel
     * (`Http3Exception.ConnectRejected` with its `proxy-status`), under `http3 { discovery = H1Only }` or while
     * `http3Allowed` says no (UnsupportedOperationException). `Alt-Svc` is neither used nor learned for it, and the origin's
     * name is resolved by the proxy, not here. WebTransport refuses such URLs unless `http3 { webTransportIgnoresConnectUdpProxy }`.
     * The QUIC connection to the proxy itself has [proxyTls] (by default the origin's trust without what names the origin,
     * and no client certificate), as an `https://` proxy; the origin's connection inside the tunnel has [trust],
     * [identity] and [tls]. docs/guide/ktor.md, "HTTP/3 through a CONNECT-UDP proxy".
     */
    @ExperimentalKuicksilverApi
    public var connectUdpProxy: ConnectUdpProxy? = null

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

    /**
     * Whether a proxy auto-configuration (PAC) script the system settings name gets a `wss://` WebSocket's whole URI
     * with its resource name (path and query), as RFC 6455 section 4.1 asks, on Apple platforms and Windows
     * ([ProxyResolvers.System]); the script must be given inline in the settings (Apple), by an `https://` URL or by a
     * local `file:` URL (`file:///…`; one with a host, `file://srv/share/p.pac`, is fetched over SMB and does not count). Off by default: every script gets `wss://host[:port]/` only, as Chrome, Firefox and Android give
     * `https` and `wss` URLs to PAC scripts, since a script can send what it is given out through `dnsResolve`
     * (CVE-2016-3763, CVE-2016-5134). A script found by WPAD (automatic detection) or fetched over plain `http://`
     * never gets more than that, whatever this says: whoever answers on the local network writes it. `ws://` URIs reach
     * every script whole, `http` and `https` ones as their origin. On Apple platforms the PAC URL CFNetwork reports
     * must equal the settings' string exactly; one written otherwise gets the origin. docs/guide/ktor.md, "Proxies".
     */
    @ExperimentalKuicksilverApi
    public var pacFullWebSocketUrl: Boolean = false

    /**
     * Resolves host names to the addresses the engine connects to, over TCP and QUIC, with Happy Eyeballs (RFC 8305) on what
     * it answers: [Dns.System] (the default: the system's resolver, as before 0.3.0) or your own, after OkHttp's `Dns`, for
     * another DNS server (DNS over HTTPS), fixed addresses or a policy of your own; [Dns.blocking] adapts a blocking one, and
     * a [FamilyDns] answers each address family on its own (RFC 8305 section 3). Its lookup is part of connecting
     * ([connectTimeout] bounds it), it never gets address literals, it is asked for an HTTP proxy's name but never for the
     * origin's behind it, and its answers never stand in for the host name in TLS: SNI and the certificate check use the
     * URL's host. See [Dns] for the whole contract and docs/guide/ktor.md, "Name resolution".
     */
    @ExperimentalKuicksilverApi
    public var dns: Dns = Dns.System

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

    /** Encrypted Client Hello (RFC 9849): configurations per host, GREASE, the HTTPS records' `ech`; change it with [ech]. */
    @ExperimentalKuicksilverApi
    public val ech: EchClientConfig = EchClientConfig()

    /** Configures [ech] in place: `engine { ech { configLists = mapOf("example.com" to list) } }`. */
    @ExperimentalKuicksilverApi
    public fun ech(block: EchClientConfig.() -> Unit) {
        ech.apply(block)
    }

    /** Configures [http3] in place: `engine { http3 { discovery = Http3DiscoveryMode.Preferred } }`. */
    public fun http3(block: Http3ClientConfig.() -> Unit) {
        http3.apply(block)
    }
}
