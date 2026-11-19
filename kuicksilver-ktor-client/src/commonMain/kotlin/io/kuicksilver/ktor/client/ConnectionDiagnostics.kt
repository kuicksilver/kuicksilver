// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.PathInfo
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
 * The HTTP/3 connection of a call. From the response head until the call ends, [ProtocolDiagnostics.connection] takes a
 * new one from the live connection at each read; when the call ends (its body read or abandoned) one last snapshot is
 * taken and kept, so a call read after its body finished shows the connection as it was then. A call that failed on the
 * connection keeps the one taken at the failure.
 *
 * Plain data only: it names the connection ([connectionId]) but holds no handle to it, so neither a response nor a failed
 * call's exception that carries the diagnostics keeps the connection (its buffers, its endpoint) in memory. For the live
 * connection, join [connectionId] with what `http3 { connectionListener }` hears.
 *
 * @property connectionId The connection's [ConnectionInfo.id] (the original destination connection ID in hex, stable for
 *   its life, the name of its qlog trace): what `http3 { connectionListener }` and [ConnectFailure.connectionId] call it.
 *   Null only for a connection outside this library.
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
    public val connectionId: String?,
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

/**
 * Where a connection setup failed ([ConnectFailure.stage]). The first three name what a connect timeout spent its time
 * waiting for before any address was tried; the others are steps with an address.
 */
@ExperimentalKuicksilverApi
public enum class ConnectStage {
    /** The name lookup of the host (or of the proxy) had not given an address to try yet. */
    NameLookup,

    /** A connection slot of the route (`maxConnectionsPerRoute`): every one was in use, and none came free in time. */
    PoolWait,

    /**
     * Another request's HTTP/2 connect to the route (one at a time, RFC 9113 section 9.1): this request waited for it to
     * share that connection, and it did not come in time.
     */
    H2DialWait,

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
 * still running then, at its step; or once, without an [address], at what the time went to before any address was tried
 * ([ConnectStage.NameLookup], [ConnectStage.PoolWait], [ConnectStage.H2DialWait]).
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
 * @property connectionId For a [ConnectStage.QuicHandshake] failure, the [io.kuicksilver.quic.ConnectionInfo.id] of the
 *   QUIC connection this attempt made (the original destination connection ID, the name `connectionListener` and qlog
 *   know it by), taken from the connection the attempt's own `connect` created; null for TCP and when none was made.
 */
@ExperimentalKuicksilverApi
public class ConnectFailure internal constructor(
    public val transport: Transport,
    public val stage: ConnectStage,
    public val address: InetSocketAddress?,
    public val viaProxy: Boolean,
    public val cause: Throwable,
    public val quicProgress: QuicHandshakeProgress? = null,
    public val connectionId: String? = null,
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
 * which setups failed and where. Null for an exception no Kuicksilver engine call threw and for a cancellation.
 *
 * A connection's failure (a QUIC connection's end, an HTTP/3 or HTTP/2 connection error, a shared setup's failure) is one
 * instance for every request on the connection and for the connection listener: the engine never puts a call's
 * diagnostics on it. A call that fails with it in the engine throws its own copy (same type, fields and cause) that carries
 * them, and `callFailed` gets that copy; the instance itself, which a call reading its response body, `onClosed` and
 * `QuicConnection.closed` get, carries none. [KuicksilverEventListener.callFailed] has the request's own diagnostics always.
 *
 * The engine attaches it as a suppressed exception (`FailureDiagnostics`) whose message is one line: the transport that
 * failed, HTTP/3's failure by its type and reason, the stages of the setups that failed, the attempts — never a URL, a
 * host, an address or a connection ID, so a printed stack trace shows no more of the call than the exception itself does.
 * On the JVM and Android it carries no stack of its own (one line in a printed trace); on Kotlin/Native its stack, the
 * engine's, is printed under it.
 *
 * A request timeout of Ktor's `HttpTimeout` (`HttpRequestTimeoutException`) reaches the engine as the cancellation of the
 * call: the engine attaches the diagnostics to that exception, which is the one Ktor throws. With coroutines' stack-trace
 * recovery on (a debug build: assertions enabled) the exception thrown can be a copy whose cause is the original; the
 * engine attaches them to that original as well, and this looks through the causes. A cancellation of the call by the
 * application carries none; [KuicksilverEventListener.callFailed] has them in the request's attributes.
 */
@ExperimentalKuicksilverApi
public val Throwable.kuicksilverDiagnostics: ProtocolDiagnostics?
    get() {
        var e: Throwable? = this
        var depth = 0
        while (e != null && depth++ < 16) {
            val now: Throwable = e
            val carrier = withCarrierLock(now) { now.suppressedExceptions.firstNotNullOfOrNull { it as? FailureDiagnostics } }
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
    if (e is CancellationException) return // the caller looks for the cause Ktor throws (settleFailure)
    withCarrierLock(e) {
        val existing = e.suppressedExceptions.firstNotNullOfOrNull { it as? FailureDiagnostics }
        when {
            existing == null -> e.addSuppressed(FailureDiagnostics(d))
            existing.diagnostics !== d -> existing.shared = true
        }
    }
}

/**
 * Runs [block] (a scan or change of [e]'s suppressed exceptions) under the lock that guards them: on the JVM and Android
 * [e]'s own monitor, the one `addSuppressed` and `getSuppressed` take; on Kotlin/Native, whose suppressed list is not
 * thread-safe, one process-wide mutex (failures are rare, and the block is a short list scan).
 */
internal expect fun <T> withCarrierLock(
    e: Throwable,
    block: () -> T,
): T

/**
 * A snapshot of the HTTP/3 connection [conn] for a call that took it when its [ConnectionInfo.pathChanges] was
 * [startChanges]: one statistics read and one object, made at a read of [ProtocolDiagnostics.connection] during the call,
 * when the call failed on it, or when it ended; never per packet.
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
        info?.id,
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

/**
 * Settles [d] for a call that failed with [e] and returns what the call throws: [e] carrying [d]
 * ([kuicksilverDiagnostics]); for a connection's failure, which every stream of the connection (and the connection
 * listener) gets as one instance, this call's own copy carrying [d] (the type, fields and cause stay), or [e] carrying
 * nothing when it cannot be copied. The connection kept is the one of the transport the failure came from, the protocol
 * that of the last attempt.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
internal fun settleFailure(
    d: ProtocolDiagnostics,
    e: Throwable,
): Throwable {
    // a cancellation carries nothing; Ktor's request timeout cancels the call with its HttpRequestTimeoutException as
    // the cause, the exception Ktor then throws: that one carries the diagnostics
    val carrier =
        if (e is CancellationException) {
            generateSequence(e.cause) {
                it.cause
            }.take(8).firstOrNull { it !is CancellationException }
        } else {
            e
        }
    if (carrier == null) return e
    d.failed = true
    val t = d.transport
    val c = d.connection
    if (c != null && c.transport != t) d.connection = null // a connection of the side that did not fail last
    d.protocol =
        when (t) {
            Transport.Quic -> HttpProtocolVersion.HTTP_3_0
            Transport.Tcp -> d.connection?.protocol ?: HttpProtocolVersion.HTTP_1_1
            null -> d.protocol
        }
    if (d.isConnectionWide(carrier)) {
        // never on the shared instance: another call reading its body, or an onClosed listener, would see this call's
        val own =
            when {
                carrier !== e -> {
                    null
                }

                e is io.kuicksilver.http2.runtime.Http2Exception.ConnectionClosed -> {
                    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                    e.copyForCall()
                }

                // a shared setup's connect timeout (Ktor's type, which coroutines cannot copy): the same message and cause
                e is io.ktor.client.network.sockets.ConnectTimeoutException -> {
                    io.ktor.client.network.sockets.ConnectTimeoutException(e.message ?: "Connect timeout has expired", e.cause).also { c ->
                        withCarrierLock(e) { e.suppressedExceptions.toList() }.forEach(c::addSuppressed)
                    }
                }

                else -> {
                    (e as? kotlinx.coroutines.CopyableThrowable<*>)?.createCopy()
                }
            }
        if (own == null) return e
        attachDiagnostics(own, d)
        return own
    }
    attachDiagnostics(carrier, d)
    // coroutines' stack-trace recovery (debug builds) hands the engine a copy whose cause is the original exception of
    // the same type, and copies that original again on the way to the application, dropping the first copy: the
    // original carries them too, unless it is a connection's shared failure
    var original: Throwable = carrier
    while (true) {
        val c = original.cause ?: break
        if (c::class != original::class || c === original) break
        original = c
    }
    if (original !== carrier && !d.isConnectionWide(original)) attachDiagnostics(original, d)
    return e
}
