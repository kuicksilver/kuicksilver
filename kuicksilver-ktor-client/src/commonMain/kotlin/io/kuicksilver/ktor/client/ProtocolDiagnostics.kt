// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.util.AttributeKey
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.ktor.client.h3.H3NotSent
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.tls.TlsException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * Which protocol served a call and, when it was not HTTP/3, why (docs/guide/ktor.md, "Why did this request not use
 * HTTP/3?"); which connection served it ([connection]); and for a call that failed, which transport the failure came from
 * ([transport]) and which connection setups failed ([connectFailures]). The engine attaches one to every response it
 * returns: read it with [HttpResponse.kuicksilverDiagnostics]. A call that fails has no response: its exception carries
 * the diagnostics instead ([Throwable.kuicksilverDiagnostics], docs/guide/ktor.md, "Why did this call fail?"); when the
 * HTTP/3 and HTTP/1.1 setups both failed, the HTTP/1.1 failure is thrown with the HTTP/3 one in `suppressed`, and
 * [h3Failure] is that HTTP/3 one.
 *
 * It lives as long as the response (it is one of the call's attributes) and holds the HTTP/3 failure, if any, by
 * reference; the engine keeps no copy of it.
 *
 * The engine puts a new one into the request's attributes when the call reaches it, fills it while the call runs (code
 * that reads [KuicksilverDiagnosticsKey] from the request before the response, a listener say, sees it incomplete) and,
 * when the call fails, removes it once [KuicksilverEventListener.callFailed] returned (in that callback the request's
 * attributes still hold the failed call's). Read it from the response: a request built from an earlier one (Ktor's
 * redirect copies the attributes with `takeFrom`) carries the earlier response's diagnostics until the engine replaces
 * them, so a plugin that runs before the engine sees stale ones; and when an interceptor sends one request builder
 * through the engine twice, each engine call gets its own object and the attributes keep the last.
 *
 * The fields the engine fills while the call runs ([connection], [transport], [connectFailures]) are safe to read from
 * any thread; the others are final once the response or the failure is out.
 */
@ExperimentalKuicksilverApi
public class ProtocolDiagnostics internal constructor() {
    /**
     * The protocol the response came over: `HTTP_3_0`, `HTTP_2_0` or `HTTP_1_1`. For a failed call, the protocol of the
     * attempt that failed last: `HTTP_3_0` over QUIC, else the TCP connection's (`HTTP_1_1` when it failed before one was
     * agreed).
     */
    public var protocol: HttpProtocolVersion = HttpProtocolVersion.HTTP_1_1
        internal set

    /**
     * The transport the response (or, for a failed call, the thrown failure) came over: [Transport.Quic] for HTTP/3,
     * [Transport.Tcp] for HTTP/1.1 and HTTP/2. A failed call over TCP after HTTP/3 had failed has [h3Failure] too. Null only
     * for a call that failed before it tried either (a configuration the request cannot use, such as an `http://` URL in
     * `Http3DiscoveryMode.H3Only`). While the call runs it follows the attempt in progress.
     */
    @kotlin.concurrent.Volatile
    public var transport: Transport? = null
        internal set

    /**
     * The connection behind the call ([QuicConnectionSnapshot] or [TcpConnectionSnapshot]), on the [transport] the call
     * ended on: the one that served the response, or the one the failure came from when a connection was in hand (a TCP
     * connection whose TLS handshake failed included); null for a failure before any connection (every address refused, a
     * QUIC handshake that never completed: see [connectFailures]).
     *
     * During an HTTP/3 call, from its response head until the call ends, each read takes a new snapshot of the live
     * connection, so two reads return two objects (`d.connection !== d.connection`) with the values of their moment; when
     * the call ends one last snapshot is taken and every read returns it from then on.
     */
    public var connection: ConnectionSnapshot?
        // during an HTTP/3 call, from its response head to its end, each read takes a new snapshot of the live connection
        // (so two reads are two objects); the one taken at the end stays (and no handle to the connection is kept after it)
        get() {
            val l = liveQuic ?: return settled
            return runCatching { quicSnapshot(l.conn, l.reused, l.startChanges) }.getOrNull()?.also { lastLive = it } ?: lastLive ?: settled
        }
        internal set(value) {
            settled = value
            liveQuic = null
        }

    /** The last snapshot a read during the call made: kept when the one at the call's end cannot be made. */
    @kotlin.concurrent.Volatile
    internal var lastLive: ConnectionSnapshot? = null

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val connectionWide = kotlin.concurrent.atomics.AtomicReference(emptyList<Throwable>())

    /**
     * [failures] are the connection's own end, one instance for every call on it (the HTTP/3 session's `closed` value, the
     * QUIC connection's close reason, the HTTP/2 connection's close cause, a shared setup's failure): this call never puts
     * its diagnostics on them, only on its own copy. Called by the pools when a call fails on a connection.
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal fun connectionWide(vararg failures: Throwable?) {
        val add = failures.filterNotNull()
        if (add.isEmpty()) return
        while (true) {
            val now = connectionWide.load()
            if (connectionWide.compareAndSet(now, now + add)) return
        }
    }

    /** Whether [t] is one of the instances [connectionWide] recorded (by identity). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal fun isConnectionWide(t: Throwable): Boolean = connectionWide.load().any { it === t }

    @kotlin.concurrent.Volatile
    private var settled: ConnectionSnapshot? = null

    /** The HTTP/3 connection a running call is on, from its response head to its end: [connection] reads it when asked. */
    internal class LiveQuic(
        val conn: io.kuicksilver.quic.QuicConnection,
        val reused: Boolean,
        val startChanges: Int,
    )

    @kotlin.concurrent.Volatile
    internal var liveQuic: LiveQuic? = null

    /** The transport of [connection] without building a snapshot. */
    internal val connectionTransport: Transport? get() = if (liveQuic != null) Transport.Quic else settled?.transport

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val failures = kotlin.concurrent.atomics.AtomicReference(emptyList<ConnectFailure>())

    /**
     * Every connection setup that failed for this call, in the order the failures came, at most 16
     * ([KuicksilverEventListener.connectFailed] hears the same): TCP connects to single addresses, proxy and TLS handshakes,
     * QUIC handshakes. Present on a call that succeeded another way too (a refused IPv6 address before the IPv4 one worked).
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    public val connectFailures: List<ConnectFailure> get() = failures.load()

    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal fun connectFailed(f: ConnectFailure) {
        while (true) {
            val now = failures.load()
            if (now.size >= MAX_CONNECT_FAILURES) return
            if (failures.compareAndSet(now, now + f)) return
        }
    }

    /** The call failed (for the log line and the text of the exception's carrier). */
    internal var failed: Boolean = false

    /** Why the engine chose [protocol] for the last attempt: the reason [KuicksilverEventListener.protocolSelected] heard. */
    public var reason: ProtocolReason = ProtocolReason.Configuration
        internal set

    /**
     * Why the call did not go over HTTP/3; null when it did. See [FallbackReason] for what each value means and what to
     * check. A call over HTTP/2 has the reason HTTP/3 was not used, as one over HTTP/1.1. The one exception is
     * [FallbackReason.H2Refused]: the call went over HTTP/1.1 because the server refused HTTP/2, and the reason HTTP/3 was
     * not used appears in the log line as `h3Fallback=`.
     */
    public var fallback: FallbackReason? = null
        internal set

    /**
     * The HTTP/3 failure behind [fallback] when HTTP/3 was tried for this call and failed (a lost race the HTTP/3 side lost
     * by failing, or a fallback after an HTTP/3 error); null otherwise, also for [FallbackReason.H3NotReady] and
     * [FallbackReason.BrokenAlternative] (the failure that marked the alternative broken belonged to an earlier call).
     */
    public var h3Failure: Throwable? = null
        internal set

    private var alternativeHost: String? = null
    private var alternativePort: Int = 0

    /** The HTTP/3 endpoint (`host:port`, an IPv6 address in brackets) considered for the call, when there was one. */
    public val alternative: String? get() = alternativeHost?.let { "${uriHost(it)}:$alternativePort" } // built when read

    /** Where [alternative] came from; null when there was none. */
    public var alternativeSource: AlternativeSource? = null
        internal set

    /** Whether HTTP/3 and TCP (HTTP/1.1 or HTTP/2) connection setups raced for this call (docs/guide/ktor.md, "Racing and fallback"). */
    public var raced: Boolean = false
        internal set

    private var headStartNanos: Long = -1

    /** HTTP/3's head start in the race; null when there was no race ([raced] is false). */
    public val headStart: Duration?
        get() =
            when (headStartNanos) {
                -1L -> null

                Long.MAX_VALUE -> Duration.INFINITE

                // `hardDelay = Duration.INFINITE`: HTTP/1.1 only once HTTP/3 failed
                else -> headStartNanos.nanoseconds
            }

    /**
     * How many attempts the engine made for the response: the first, plus one per repeat by the engine (a request the
     * server did not process — GOAWAY, H3_REQUEST_REJECTED — or that this client's own `closeHttp3Connections()` stopped
     * before it went out, each repeated on a new connection; a stale pooled HTTP/1.1 connection; a 417 to
     * `Expect: 100-continue`), plus one for the fallback to HTTP/1.1 when HTTP/3 had tried the request (not when the HTTP/3
     * connection could not be set up or its handshake failed: then HTTP/1.1 is the first attempt). Repeats inside the
     * HTTP/3 layer on the same connection — a 0-RTT request sent again after its early data was rejected, or after a
     * 425 Too Early — are not counted.
     */
    public var attempts: Int = 1
        internal set

    /** Why the alternative was marked broken, when [fallback] is [FallbackReason.BrokenAlternative] (for the log line). */
    internal var brokenSince: FallbackReason? = null

    /** This call's HTTP/3 failure marked the alternative broken (for the log line). */
    internal var markedBroken: Boolean = false

    /** The route answered HTTP_1_1_REQUIRED (this call, or lately): [fallback] becomes [FallbackReason.H2Refused] on HTTP/1.1. */
    internal var h2Refused: Boolean = false

    /** The reason HTTP/3 was not used, when [FallbackReason.H2Refused] took its place in [fallback] (for the log line). */
    internal var h3Fallback: FallbackReason? = null

    internal fun raced(headStart: Duration) {
        raced = true
        headStartNanos = if (headStart.isInfinite()) Long.MAX_VALUE else headStart.inWholeNanoseconds
    }

    /** No string is built here: on a call over HTTP/3 the diagnostics cost this object and its one attribute-map entry. */
    internal fun alternative(
        host: String,
        port: Int,
        source: AlternativeSource,
    ) {
        alternativeHost = host
        alternativePort = port
        alternativeSource = source
    }

    /**
     * The one line a failed call's exception carries ([FailureDiagnostics]): `kuicksilver: failed over TCP; HTTP/3 failed
     * first: Timeout (HandshakeTimeout); setups failed: QuicHandshake, TlsHandshake x2; attempts=2`. Types, reasons and
     * stages only: no URL, host, address, reason phrase or connection ID.
     */
    internal fun failureLine(): String =
        StringBuilder("kuicksilver: failed")
            .apply {
                append(
                    when (transport) {
                        Transport.Quic -> " over QUIC"
                        Transport.Tcp -> " over TCP"
                        null -> " before a transport was tried"
                    },
                )
                h3Failure?.takeIf { transport == Transport.Tcp }?.let { f ->
                    append("; HTTP/3 failed first: ").append(f::class.simpleName)
                    fallback?.let { append(" (").append(it).append(')') }
                }
                val stages = connectFailures.groupingBy { it.stage }.eachCount()
                if (stages.isNotEmpty()) {
                    append("; setups failed: ")
                    append(stages.entries.joinToString { (stage, n) -> if (n == 1) "$stage" else "$stage x$n" })
                }
                if (attempts > 1) append("; attempts=").append(attempts)
            }.toString()

    /**
     * The details of `line` without the request: `HTTP/1.1 (fallback=HandshakeTimeout, alt=example.com:443 via AltSvc,
     * raced, headStart=10ms)`.
     */
    override fun toString(): String = StringBuilder().also { details(it) }.toString()

    /**
     * The log line for a request to [url] with [method]: `kuicksilver: GET https://example.com/path -> HTTP/1.1 (...)`. The
     * URL is scheme, host, port (when not the default) and path: never the query or the user info, which often carry
     * tokens. The HTTP/3 failure appears by its type only: a peer's reason phrase is not written to the log.
     */
    internal fun line(
        method: String,
        url: Url,
    ): String =
        StringBuilder()
            .apply {
                append("kuicksilver: ").append(method).append(' ')
                append(url.protocol.name).append("://").append(logSafe(uriHost(url.host)))
                if (url.port != url.protocol.defaultPort) append(':').append(url.port)
                append(url.encodedPath.ifEmpty { "/" })
                append(" -> ")
                details(this)
            }.toString()

    private fun details(b: StringBuilder) {
        b.append(protocol)
        var first = true

        fun item(s: String) {
            b.append(if (first) " (" else ", ").append(s)
            first = false
        }
        if (failed) item(if (transport == null) "failed" else "failed over $transport")
        fallback?.let { item("fallback=$it") }
        h3Fallback?.let { item("h3Fallback=$it") }
        alternative?.let {
            val alt = logSafe(it)
            item(if (alternativeSource == null) "alt=$alt" else "alt=$alt via $alternativeSource")
        }
        if (raced) item("raced")
        headStart?.let { item(if (it.isInfinite()) "headStart=until HTTP/3 failed" else "headStart=${it.inWholeMilliseconds}ms") }
        h3Failure?.let { item("h3Failure=${it::class.simpleName}") }
        brokenSince?.let { item("broken since: $it") }
        if (markedBroken) item("marked broken")
        if (attempts > 1) item("attempts=$attempts")
        if (!first) b.append(')')
    }
}

/**
 * [s] with every character that could end or forge a field of the log line (anything but letters, digits and `.-:[]_%~`)
 * replaced by `?`: hosts come from URLs and `Alt-Svc` headers, and the line must stay one line of known fields.
 */
internal fun logSafe(s: String): String =
    if (s.all { it.isLogSafe() }) s else buildString(s.length) { for (c in s) append(if (c.isLogSafe()) c else '?') }

private fun Char.isLogSafe(): Boolean = this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9' || this in ".-:[]_%~"

/**
 * Why a call did not go over HTTP/3 ([ProtocolDiagnostics.fallback]), with what to check:
 *
 * | Value | Meaning | What to check |
 * |---|---|---|
 * | [NotSecure] | an `http://` or `ws://` URL | HTTP/3 needs `https` (RFC 9114 section 3.1) |
 * | [Proxy] | a proxy applies to the request (HTTP/1.1 or HTTP/2 through it) | `proxy`, `proxyResolver`; `ProxyResolvers.None` connects directly |
 * | [Configuration] | `Http3DiscoveryMode.H1Only` | the discovery mode |
 * | [Http3Disabled] | `http3 { http3Allowed }` said false | your remote configuration |
 * | [NoAlternative] | `Auto` and the origin announced no `Alt-Svc` (yet) | the server's `Alt-Svc` header |
 * | [MisdirectedRequest] | the alternative answered 421 and was dropped; the origin served the request over HTTP/1.1 | the alternative's certificate and virtual hosts |
 * | [BrokenAlternative] | HTTP/3 to this alternative failed recently on this network | the log line's `broken since:` |
 * | [WebSocket] | a WebSocket without an HTTP/3 connection that allows Extended CONNECT | expected for the first WebSocket |
 * | [HandshakeTimeout] | no QUIC answer within the handshake or connect timeout | UDP to the port blocked (firewall, VPN), server down |
 * | [UdpUnreachable] | the network reported the UDP port unreachable | not reported yet: such calls show [HandshakeTimeout] |
 * | [H3NotReady] | HTTP/1.1 was ready first; HTTP/3 had not answered yet | nothing: a later call may use HTTP/3 |
 * | [Refused] | the server closed the QUIC connection (CONNECTION_REFUSED...) or offers no common QUIC version | CONNECTION_REFUSED: nothing, the server is draining, stopping or full and the next call tries HTTP/3 again; otherwise the server's QUIC listener |
 * | [TlsFailure] | the QUIC handshake failed in TLS (a certificate, no `h3` ALPN) | the certificate and ALPN of the UDP side |
 * | [Http3Error] | the HTTP/3 connection failed as a whole (a protocol error, a stateless reset, the path) | `h3Failure`, a qlog trace |
 * | [ZeroRttRejected] | the server rejected 0-RTT | nothing: the request went again |
 * | [GoAway] | the server kept refusing the request with GOAWAY | the server is shutting down |
 * | [StreamFailed] | one request stream failed and the request was repeated over HTTP/1.1 | `h3Failure` |
 * | [Other] | any other HTTP/3 failure | `h3Failure` |
 * | [H2Refused] | over HTTP/1.1: the server answered HTTP/2 with HTTP_1_1_REQUIRED (now or lately) | the server's HTTP/2 configuration; `http2 { enabled = false }` |
 *
 * New values may be added in later versions (docs/stability.md).
 */
@ExperimentalKuicksilverApi
public enum class FallbackReason {
    /** An `http://` or `ws://` request: HTTP/3 needs TLS. */
    NotSecure,

    /** A proxy applies to the request: through it only TCP (HTTP/1.1, or HTTP/2 inside the tunnel). */
    Proxy,

    /** `Http3DiscoveryMode.H1Only`. */
    Configuration,

    /** `Http3ClientConfig.http3Allowed` returned false for this request. */
    Http3Disabled,

    /** `Auto` mode without a known HTTP/3 alternative for the origin (no `Alt-Svc` yet, or it was dropped). */
    NoAlternative,

    /**
     * The HTTP/3 alternative answered 421 Misdirected Request: it is dropped from the origin's alternatives (RFC 7838
     * section 6) and the request went to the origin over HTTP/1.1.
     */
    MisdirectedRequest,

    /** The alternative is marked broken on this network: HTTP/3 failed there while HTTP/1.1 worked. */
    BrokenAlternative,

    /** A WebSocket to an origin without an open HTTP/3 connection that allows Extended CONNECT (RFC 9220). */
    WebSocket,

    /** QUIC got no answer within the handshake or connect timeout: UDP is blocked on the way, or the server is silent. */
    HandshakeTimeout,

    /**
     * The network answered with ICMP port or host unreachable. Reported once the UDP socket surfaces such errors to the
     * connection; until then these calls show [HandshakeTimeout].
     */
    UdpUnreachable,

    /** HTTP/1.1 won the race before HTTP/3 answered: HTTP/3 had not failed (yet), it was slower or is still connecting. */
    H3NotReady,

    /**
     * The server closed the connection during setup without a TLS alert, or version negotiation failed. CONNECTION_REFUSED
     * (a server in `Drain`, stopping, or with a full accept queue: RFC 9000 section 5.2.2), at the first Initial or on a
     * connection whose handshake completed into a full accept queue, is transient: the call falls
     * back to HTTP/1.1 once, the alternative is not marked broken and the next call tries HTTP/3 again. Any other code
     * marks the alternative broken.
     */
    Refused,

    /** The QUIC handshake failed in TLS: a TLS alert (`0x0100 + alert`: a certificate, no `h3` ALPN) or a local verification failure. */
    TlsFailure,

    /** The HTTP/3 connection failed as a whole: an HTTP/3 or QPACK connection error, a stateless reset, an idle timeout, no viable path. */
    Http3Error,

    /** The server rejected 0-RTT. */
    ZeroRttRejected,

    /** The server did not process the request (GOAWAY, H3_REQUEST_REJECTED) on any attempt. */
    GoAway,

    /** One request stream failed (reset, malformed response) and the idempotent request was repeated over HTTP/1.1. */
    StreamFailed,

    /** Any other HTTP/3 failure. */
    Other,

    /**
     * The call went over HTTP/1.1 because the server answered HTTP/2 with HTTP_1_1_REQUIRED (RFC 9113 section 7), on this
     * call (repeated over HTTP/1.1, when that was safe: otherwise the call failed with `Http11RequiredException`) or lately (its route offers only `http/1.1` for 5 minutes, doubling up to 2 days at
     * each new refusal). The reason HTTP/3 was not used is in the log line as `h3Fallback=`.
     */
    H2Refused,
}

/** Where the HTTP/3 endpoint of a call came from ([ProtocolDiagnostics.alternativeSource]). */
@ExperimentalKuicksilverApi
public enum class AlternativeSource {
    /** An `Alt-Svc` header of the origin (RFC 7838), in `Http3DiscoveryMode.Auto`. */
    AltSvc,

    /** The origin is in `Http3ClientConfig.quicHints`. */
    QuicHint,

    /** `Http3DiscoveryMode.Preferred`: the origin itself, by prior knowledge. */
    Preferred,

    /** `Http3DiscoveryMode.H3Only`: the origin itself, without a fallback. */
    H3Only,

    /** An HTTPS resource record of the origin (RFC 9460, `Http3ClientConfig.httpsRecords`), in `Http3DiscoveryMode.Auto`. */
    HttpsRecord,
}

/** The call attribute that holds a response's [ProtocolDiagnostics]; [HttpResponse.kuicksilverDiagnostics] reads it. */
@ExperimentalKuicksilverApi
public val KuicksilverDiagnosticsKey: AttributeKey<ProtocolDiagnostics> = AttributeKey("KuicksilverDiagnostics")

/** Which protocol served this response and why ([ProtocolDiagnostics]); null when another engine made the call. */
@ExperimentalKuicksilverApi
public val HttpResponse.kuicksilverDiagnostics: ProtocolDiagnostics?
    get() = call.attributes.getOrNull(KuicksilverDiagnosticsKey)

/**
 * What an HTTP/3 failure says about why the call is not served over HTTP/3; null for no failure (the caller reports
 * [FallbackReason.H3NotReady]: HTTP/3 did not fail, it was not ready).
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun classifyH3Failure(e: Throwable?): FallbackReason? =
    when (e) {
        null -> {
            null
        }

        is H3NotSent -> {
            classifyH3Failure(e.cause) ?: FallbackReason.Other
        }

        is ConnectTimeoutException -> {
            FallbackReason.HandshakeTimeout
        }

        is QuicException.ConnectionLost.Timeout -> {
            if (e.kind == TimeoutKind.Handshake) FallbackReason.HandshakeTimeout else FallbackReason.Http3Error
        }

        // RFC 9000 section 20.1: CRYPTO_ERROR 0x0100-0x01ff carries a TLS alert
        is QuicException.ConnectionLost.TransportClosed -> {
            when {
                e.code in 0x100L..0x1ffL -> FallbackReason.TlsFailure
                e.initiator == Initiator.Peer -> FallbackReason.Refused
                else -> FallbackReason.Http3Error
            }
        }

        is QuicException.ConnectionLost.VersionNegotiation -> {
            FallbackReason.Refused
        }

        is QuicException.ConnectionLost.ZeroRttRejected, is QuicException.StreamError.EarlyDataRejected -> {
            FallbackReason.ZeroRttRejected
        }

        is QuicException.StreamError -> {
            FallbackReason.StreamFailed
        }

        is QuicException.ConnectionLost.StatelessReset, is QuicException.ConnectionLost.NoViablePath,
        is QuicException.ConnectionLost.ApplicationClosed,
        -> {
            FallbackReason.Http3Error
        }

        is Http3Exception.RequestNotProcessed -> {
            FallbackReason.GoAway
        }

        is Http3Exception.Protocol -> {
            if (e.streamId == null) FallbackReason.Http3Error else FallbackReason.StreamFailed
        }

        is Http3Exception.Qpack, is Http3Exception.Settings -> {
            FallbackReason.Http3Error
        }

        is Http3Exception.MessageError, is Http3Exception.FieldSectionTooLarge -> {
            FallbackReason.StreamFailed
        }

        is TlsException -> {
            FallbackReason.TlsFailure
        }

        else -> {
            FallbackReason.Other
        }
    }
