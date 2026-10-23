// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.HttpClientEngineConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.KuicksilverLogger
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

    /** HTTP/1.1 only. */
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
    override fun equals(other: Any?): Boolean = other is HostPort && other.host == host && other.port == port

    override fun hashCode(): Int = host.hashCode() * 31 + port

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

    /** Forget alternatives without `persist=1` when the network changes (RFC 7838 section 2.2; off like browsers). */
    public var clearOnNetworkChange: Boolean = false

    /** Head start of HTTP/3 over HTTP/1.1; null: 1.5 x the host's smoothed RTT, or 250 ms without history, clamped to 100 ms..2 s. */
    public var hardDelay: Duration? = null

    /** Identifies the current network; a change resets "broken" marks and QUIC confirmation. null: one network. */
    public var networkId: () -> String? = { null }

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
     * (RFC 8446 section 8): turn this on only for servers whose safe methods are free of side effects.
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
}

/** Configuration of `HttpClient(Kuicksilver)`. */
public class KuicksilverEngineConfig : HttpClientEngineConfig() {
    /** Server verification for both HTTP/3 and HTTP/1.1 (the fallback keeps the same pins and trust, threat-model 3.18). */
    public var trust: TrustConfig = TrustConfig.Platform

    /** Client certificate, when servers ask for one. */
    public var identity: TlsIdentity? = null

    /**
     * Further TLS settings, applied after [trust] and [identity] (so the block may replace them). ALPN and the server name
     * come from the request (`h3` or `http/1.1`, the URL's host) and are set after the block: values the block gives them
     * are not used. Verify another name with `TrustConfig.ExpectedName` instead.
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
     * HTTP/1.1 connections open at once across all routes, idle ones included (CIO's `maxConnectionsCount`, the same
     * default 1000). A request beyond it waits, in FIFO order, within the connect timeout; when other routes hold idle
     * connections, the oldest one is closed to make room instead. HTTP/3 multiplexes and is limited per origin instead.
     */
    @ExperimentalKuicksilverApi
    public var maxConnectionsCount: Int = 1000

    /**
     * HTTP/1.1 connections open at once to one route (scheme, host, port and proxy), idle ones included (CIO's
     * `endpoint.maxConnectionsPerRoute`, the same default 100); further requests to it wait in FIFO order within the
     * connect timeout, failing with `ConnectTimeoutException` when no connection frees up in time.
     */
    @ExperimentalKuicksilverApi
    public var maxConnectionsPerRoute: Int = 100

    /**
     * How long a connection without requests is kept: an idle HTTP/1.1 keep-alive connection, or an HTTP/3 connection
     * with no request in flight (5 minutes, as OkHttp's keep-alive; QUIC's own idle timeout may end it earlier). A
     * background task closes expired connections and drops the bookkeeping of origins without connections.
     */
    @ExperimentalKuicksilverApi
    public var idleTimeout: Duration = 5.minutes

    /**
     * Age after which a connection takes no new requests: a pooled HTTP/1.1 connection is closed instead of reused, and
     * new HTTP/3 requests go to a new connection while the old one finishes its requests and then closes. Infinite by
     * default, as in OkHttp and CIO; a finite value spreads load after DNS or load-balancer changes.
     */
    @ExperimentalKuicksilverApi
    public var maxConnectionLifetime: Duration = Duration.INFINITE

    /** Connect timeout when `HttpTimeout` sets none (TCP + TLS, or the QUIC handshake). */
    public var connectTimeout: Duration = 10.seconds

    /**
     * Happy Eyeballs (RFC 8305) for HTTP/1.1's TCP connects, to the origin and to a proxy: the addresses a name resolves to
     * are tried with the IPv6 and IPv4 families alternating, starting the next attempt when this delay has passed or the
     * previous attempt failed, and the first connection wins (the others are cancelled or closed). 250 ms by default, as
     * RFC 8305 section 8 recommends; 10 ms to 2 s is allowed, or [Duration.INFINITE] to try one address after another as
     * in 0.2. Any other value fails the engine's creation with [IllegalArgumentException]. [connectTimeout] bounds all
     * attempts together. HTTP/3 connects to the first address of the same resolution (no race between addresses): a
     * broken first family loses the h3/h1 race, but with `Http3DiscoveryMode.H3Only` there is no race and such a request
     * fails at the connect timeout.
     */
    @ExperimentalKuicksilverApi
    public var connectionAttemptDelay: Duration = 250.milliseconds

    /**
     * Credentials for the proxy (`proxy`): SOCKS5 username/password (RFC 1929), offered to a SOCKS5 proxy and sent only
     * when it picks that method, or `Proxy-Authorization: Basic` on an HTTP proxy's CONNECT and absolute-form requests,
     * sent with the first request (no 407 round trip) unless the request sets its own `Proxy-Authorization`. Off the JVM
     * the proxy URL's user info (`http://user:password@proxy:3128`) wins over these. Null (the default) for none. Both go
     * in clear to the proxy (RFC 1929 section 5, RFC 7617 section 4), never to the origin, and never into the engine's
     * logs or events.
     */
    @ExperimentalKuicksilverApi
    public var proxyCredentials: ProxyCredentials? = null

    /** Replaces the system resolver for both pools (tests: names and addresses the test owns). */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    internal var resolverForTest: (suspend (String, Int) -> List<io.kuicksilver.ktor.network.TcpAddress>)? = null

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

    /** Configures [http3] in place: `engine { http3 { discovery = Http3DiscoveryMode.Preferred } }`. */
    public fun http3(block: Http3ClientConfig.() -> Unit) {
        http3.apply(block)
    }
}
