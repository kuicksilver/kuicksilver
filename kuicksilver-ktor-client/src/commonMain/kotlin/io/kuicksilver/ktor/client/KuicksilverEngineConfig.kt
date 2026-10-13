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

    /** Curl's soft timeout: start HTTP/1.1 when no UDP datagram came back within this delay. Accepted but not acted on in v1 (the race uses the head start only); see docs/guide/ktor.md. */
    public var softDelay: Duration = 100.milliseconds

    /** Head start of HTTP/3 over HTTP/1.1; null: 1.5 x the host's smoothed RTT, or 250 ms without history, clamped to 100 ms..2 s. */
    public var hardDelay: Duration? = null

    /** Identifies the current network; a change resets "broken" marks and QUIC confirmation. null: one network. */
    public var networkId: () -> String? = { null }

    /** HTTP/3 settings of the engine's connections. */
    public var settings: Http3Settings = Http3Settings.Default

    /** The client QUIC endpoint (dispatcher, crypto provider, socket factory). */
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
}

/** Configuration of `HttpClient(Kuicksilver)`. */
public class KuicksilverEngineConfig : HttpClientEngineConfig() {
    /** Server verification for both HTTP/3 and HTTP/1.1 (the fallback keeps the same pins and trust, threat-model 3.18). */
    public var trust: TrustConfig = TrustConfig.Platform

    /** Client certificate, when servers ask for one. */
    public var identity: TlsIdentity? = null

    /** Further TLS settings applied after the engine's (ALPN and server name come from the request). */
    public var tls: TlsConfig.Builder.() -> Unit = {}

    /** QUIC transport settings of HTTP/3 connections. */
    public var quic: QuicConfig = QuicConfig.Default

    /**
     * Idle HTTP/1.1 keep-alive connections kept per route (origin and proxy) for reuse; it does not limit open
     * connections, [maxConnectionsPerRoute] and [maxConnectionsCount] do. 0 keeps none.
     */
    public var maxConnectionsPerHost: Int = 4

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
