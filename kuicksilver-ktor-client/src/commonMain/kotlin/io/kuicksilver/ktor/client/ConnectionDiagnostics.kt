// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.PathInfo
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration

/** The transport a call, or one attempt of it, went over ([ProtocolDiagnostics.transport], [ConnectFailure.transport]). */
@ExperimentalKuicksilverApi
public enum class Transport {
    /** QUIC over UDP: HTTP/3. */
    Quic,

    /** TCP, with TLS for `https`: HTTP/1.1 or HTTP/2. */
    Tcp,
}

/**
 * The connection behind a call as the engine saw it ([ProtocolDiagnostics.connection], docs/guide/ktor.md, "Which
 * connection served this call?"): a [QuicConnectionSnapshot] for HTTP/3, a [TcpConnectionSnapshot] for HTTP/1.1 and
 * HTTP/2. An instance never changes; the engine replaces it with a newer one (an HTTP/3 call's when its response ended).
 */
@ExperimentalKuicksilverApi
public sealed class ConnectionSnapshot {
    /** [Transport.Quic] or [Transport.Tcp]. */
    public abstract val transport: Transport

    /** `HTTP_3_0`, `HTTP_2_0` or `HTTP_1_1`; null for a TCP connection that failed before a protocol was agreed (in TLS). */
    public abstract val protocol: HttpProtocolVersion?

    /** The local address of the socket, when known: the active path's for QUIC. */
    public abstract val localAddress: InetSocketAddress?

    /** The address the connection goes to (the proxy's through a proxy): the active path's peer for QUIC. */
    public abstract val remoteAddress: InetSocketAddress?

    /** Whether the call took a connection that was open before it (pooled, or shared with other calls) rather than a new one. */
    public abstract val reused: Boolean
}

/**
 * The HTTP/3 connection of a call: taken when its response head arrived (or, for a call that failed on it, at the
 * failure) and again when its response ended, the body read or abandoned. The second replaces the first in
 * [ProtocolDiagnostics.connection], so a call read after its body finished shows the connection as it was then.
 *
 * @property info The connection's diagnostics handle, the one `http3 { connectionListener }` hears: its [ConnectionInfo.id]
 *   names it (stable for the connection's life), and its `paths` and `connection.stats` are live. Null only for a connection
 *   outside this library.
 * @property path The active path at the snapshot, with the connection IDs on it (linkable identifiers: see [PathInfo]).
 * @property paths Every path at the snapshot, the active one first.
 * @property smoothedRtt The active path's smoothed RTT at the snapshot (RFC 9002 section 5.3).
 * @property minRtt The active path's lowest RTT sample at the snapshot (RFC 9002 section 5.2).
 * @property rttVariation The active path's RTT variation at the snapshot.
 * @property pathChanges How many times the connection moved to another path between the moment this call took it and the
 *   snapshot: migrations, NAT rebindings, a move to the server's preferred address ([ConnectionInfo.pathChanges]). With
 *   requests sharing the connection, a move counts for every call running at the time.
 */
@ExperimentalKuicksilverApi
public class QuicConnectionSnapshot internal constructor(
    override val reused: Boolean,
    public val info: ConnectionInfo?,
    public val path: PathInfo?,
    public val paths: List<PathInfo>,
    public val smoothedRtt: Duration,
    public val minRtt: Duration,
    public val rttVariation: Duration,
    public val pathChanges: Int,
) : ConnectionSnapshot() {
    override val transport: Transport get() = Transport.Quic
    override val protocol: HttpProtocolVersion get() = HttpProtocolVersion.HTTP_3_0
    override val localAddress: InetSocketAddress? get() = path?.localAddress
    override val remoteAddress: InetSocketAddress? get() = path?.remoteAddress

    /** For logs: the path and the RTT, never a connection ID (linkable identifiers, see [PathInfo]). */
    override fun toString(): String =
        "QuicConnectionSnapshot(path=$path, srtt=$smoothedRtt, minRtt=$minRtt, pathChanges=$pathChanges, reused=$reused)"
}

/**
 * The TCP connection of a call (HTTP/1.1 or HTTP/2): taken once the connection was in hand, or when its TLS handshake
 * failed (then [protocol] is null and [ProtocolDiagnostics.connectFailures] says how).
 *
 * @property alpn The protocol the server chose in ALPN (`h2`, `http/1.1`), null without TLS or ALPN.
 * @property viaProxy Whether the connection goes through a proxy; [remoteAddress] is then the proxy's.
 * @property secure Whether the connection carries TLS (to the origin, inside a tunnel through a proxy).
 */
@ExperimentalKuicksilverApi
public class TcpConnectionSnapshot internal constructor(
    override val protocol: HttpProtocolVersion?,
    override val localAddress: InetSocketAddress?,
    override val remoteAddress: InetSocketAddress?,
    override val reused: Boolean,
    public val alpn: String?,
    public val viaProxy: Boolean,
    public val secure: Boolean,
) : ConnectionSnapshot() {
    override val transport: Transport get() = Transport.Tcp

    /** For logs. */
    override fun toString(): String =
        "TcpConnectionSnapshot(${protocol ?: "no protocol"}, $localAddress -> $remoteAddress, alpn=$alpn, " +
            "viaProxy=$viaProxy, reused=$reused)"
}

/** Where a connection setup failed ([ConnectFailure.stage]). */
@ExperimentalKuicksilverApi
public enum class ConnectStage {
    /** The TCP connect to one address (refused, unreachable, reset). */
    TcpConnect,

    /** The proxy's own handshake: HTTP CONNECT or SOCKS5. */
    ProxyHandshake,

    /** The TLS handshake over TCP: an alert from the server ([io.kuicksilver.tls.TlsException.AlertReceived]), a certificate. */
    TlsHandshake,

    /** The QUIC handshake with one address (its TLS included): a timeout, an alert, a refusal, a version mismatch. */
    QuicHandshake,
}

/** How far a QUIC handshake that failed or timed out got ([ConnectFailure.quicProgress]). */
@ExperimentalKuicksilverApi
public enum class QuicHandshakeProgress {
    /** Not one packet came back from the server: UDP blocked on the way, a server that is down or silent on this port. */
    NoPacketReceived,

    /** The server answered (its Initial packets were received and decrypted), but the handshake did not complete. */
    HandshakeStarted,
}

/**
 * One connection setup that failed for a call ([KuicksilverEventListener.connectFailed], [ProtocolDiagnostics.connectFailures]),
 * whether or not the call then succeeded another way (another address, the other transport). An attempt the engine
 * cancelled because another one won (the address race, the HTTP/3 and TCP race) is no failure and is not reported. The
 * connect timeout ending a setup is one: reported with the call's `ConnectTimeoutException` as [cause], once per attempt
 * still running then (or once, with a null [address], when none had started: the name lookup or the wait for a pooled
 * connection used the time).
 *
 * @property transport [Transport.Tcp] or [Transport.Quic].
 * @property stage Where it failed (for a timeout: the step the attempt was in).
 * @property address The address the attempt went to: the proxy's through a proxy; null when the failure came before one
 *   was known.
 * @property viaProxy Whether the attempt went through a proxy.
 * @property cause What failed: for a TLS alert from the server an [io.kuicksilver.tls.TlsException.AlertReceived] (its
 *   `description`, e.g. `protocol_version`), possibly as the cause of another exception; for the connect timeout the
 *   call's `ConnectTimeoutException`; for a QUIC handshake that timed out on its own a `QuicException.ConnectionLost.Timeout`.
 * @property quicProgress For a [ConnectStage.QuicHandshake] failure, how far the handshake got: no packet from the server,
 *   or started; null for TCP, and when the connection was never opened (the endpoint could not be bound).
 */
@ExperimentalKuicksilverApi
public class ConnectFailure internal constructor(
    public val transport: Transport,
    public val stage: ConnectStage,
    public val address: InetSocketAddress?,
    public val viaProxy: Boolean,
    public val cause: Throwable,
    public val quicProgress: QuicHandshakeProgress? = null,
) {
    /** For logs: `TlsHandshake to 192.0.2.1:443 failed: AlertReceived: ...`. */
    override fun toString(): String =
        "$stage to ${address ?: "?"}${if (viaProxy) " (proxy)" else ""}${quicProgress?.let { " ($it)" } ?: ""} failed: " +
            "${cause::class.simpleName}: ${cause.message}"
}

/** At most this many [ConnectFailure]s are kept per call: an endpoint with many addresses must not grow it without end. */
internal const val MAX_CONNECT_FAILURES = 16

/**
 * The [ProtocolDiagnostics] of the call that failed with this exception, or one of its causes (docs/guide/ktor.md, "Why
 * did this call fail?"): [ProtocolDiagnostics.transport] says whether the failure came over QUIC or TCP,
 * [ProtocolDiagnostics.h3Failure] what HTTP/3's failure was when TCP came after it, [ProtocolDiagnostics.connectFailures]
 * which setups failed and where. Null for an exception no Kuicksilver engine call threw, a cancellation, and an exception
 * that ended several calls at once (one connection's failure shared by its requests: the engine cannot tell whose it would
 * be, so none says; read the request's diagnostics in [KuicksilverEventListener.callFailed] then).
 *
 * The engine attaches it as a suppressed exception (`FailureDiagnostics`) whose message is one line: the transport that
 * failed, HTTP/3's failure by its type and reason, the stages of the setups that failed, the attempts — never a URL, a
 * host, an address or a connection ID, so a printed stack trace shows no more of the call than the exception itself does.
 * On the JVM and Android it carries no stack of its own (one line in a printed trace); on Kotlin/Native its stack, the
 * engine's, is printed under it.
 *
 * A request timeout of Ktor's `HttpTimeout` (`HttpRequestTimeoutException`) reaches the engine as the cancellation of the
 * call: the engine attaches the diagnostics to that exception, which is the one Ktor throws. With coroutine stack-trace
 * recovery on (a debug build: assertions enabled) Ktor may throw a copy of it without them. A cancellation of the call by
 * the application carries none. In both cases [KuicksilverEventListener.callFailed] has them in the request's attributes.
 */
@ExperimentalKuicksilverApi
public val Throwable.kuicksilverDiagnostics: ProtocolDiagnostics?
    get() {
        var e: Throwable? = this
        var depth = 0
        while (e != null && depth++ < 16) {
            val carrier = withCarrierLock { e.suppressedExceptions.firstNotNullOfOrNull { it as? FailureDiagnostics } }
            if (carrier != null) return if (carrier.shared) null else carrier.diagnostics
            e = e.cause
        }
        return null
    }

/** Carries a failed call's diagnostics on its exception ([kuicksilverDiagnostics]). */
@OptIn(ExperimentalKuicksilverApi::class)
internal class FailureDiagnostics(
    val diagnostics: ProtocolDiagnostics,
) : Exception(diagnostics.failureLine()) {
    init {
        dropStackTrace(this) // one line in a printed stack trace (JVM and Android)
    }

    /** Another call failed with the same exception: neither call's diagnostics can be told from it. */
    @kotlin.concurrent.Volatile var shared = false
}

/** Empties [t]'s stack where the platform allows it (JVM and Android); a no-op on Kotlin/Native. */
internal expect fun dropStackTrace(t: Throwable)

/**
 * Attaches [d] to [e] for [kuicksilverDiagnostics]; an exception that carries another call's already is marked shared.
 * Never on a cancellation (often one instance for many coroutines).
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun attachDiagnostics(
    e: Throwable,
    d: ProtocolDiagnostics,
) {
    if (e is CancellationException) return // the caller looks for the cause Ktor throws (failedDiagnostics)
    withCarrierLock {
        val existing = e.suppressedExceptions.firstNotNullOfOrNull { it as? FailureDiagnostics }
        when {
            existing == null -> e.addSuppressed(FailureDiagnostics(d))
            existing.diagnostics !== d -> existing.shared = true
        }
    }
}

/** One lock for every carrier: a suppressed list is not thread-safe on Kotlin/Native, and failures are rare. */
@OptIn(ExperimentalAtomicApi::class)
private val carrierLock = AtomicInt(0)

@OptIn(ExperimentalAtomicApi::class)
private inline fun <T> withCarrierLock(block: () -> T): T {
    while (!carrierLock.compareAndSet(0, 1)) {
        // held for a list scan only
    }
    try {
        return block()
    } finally {
        carrierLock.store(0)
    }
}

/**
 * A snapshot of the HTTP/3 connection [conn] for a call that took it when its [ConnectionInfo.pathChanges] was
 * [startChanges]: one statistics read and one object, made when the response head arrived, the call failed on it or the
 * response ended, never per packet.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun quicSnapshot(
    conn: io.kuicksilver.quic.QuicConnection,
    reused: Boolean,
    startChanges: Int,
): QuicConnectionSnapshot {
    val info = conn.info
    val paths = info?.paths.orEmpty()
    val stats = conn.stats
    return QuicConnectionSnapshot(
        reused,
        info,
        paths.firstOrNull(),
        paths,
        stats.smoothedRtt,
        stats.minRtt,
        stats.rttVar,
        ((info?.pathChanges ?: 0) - startChanges).coerceAtLeast(0),
    )
}

/** [this] as a socket address, the IP as a literal (no name lookup). */
@OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal fun io.kuicksilver.ktor.network.TcpAddress.toInet(): InetSocketAddress = InetSocketAddress(hostText, port)
