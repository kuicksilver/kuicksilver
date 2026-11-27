// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.flow.StateFlow

/**
 * What a [DatagramIo] can do (ADR-0006); the portable implementations report none of the accelerated features except, on the JVM, `ecnSend` through IP_TOS.
 *
 * @property ecnSend Datagrams go out with an ECN mark, so the core validates ECN on paths through this socket (RFC 9000 section 13.4).
 * @property ecnReceive The socket reports the ECN mark of each received datagram.
 * @property gsoMaxSegments Datagrams one send may hand to the kernel as a single UDP GSO buffer; 1 without GSO.
 * @property gro Received datagrams may arrive coalesced by UDP GRO and are split again by the socket.
 * @property df The socket sets Don't Fragment in probe mode, which DPLPMTUD needs (RFC 8899); without it the MTU stays 1200.
 * @property batch Datagrams moved per system call (up to 64 on the accelerated socket, 1 on the portable ones).
 */
public class IoCapabilities
    @ExperimentalKuicksilverApi
    constructor(
        public val ecnSend: Boolean,
        public val ecnReceive: Boolean,
        public val gsoMaxSegments: Int,
        public val gro: Boolean,
        public val df: Boolean,
        public val batch: Int,
    ) {
        /** Holds [Portable]: no accelerated feature (one datagram per call; no ECN, GSO, GRO or DF), what a plain UDP socket offers. */
        public companion object {
            /** The capabilities of a plain UDP socket. */
            @OptIn(ExperimentalKuicksilverApi::class)
            public val Portable: IoCapabilities = IoCapabilities(false, false, 1, false, false, 1)
        }
    }

/** Which implementation [DatagramIo.open] prefers: the accelerated `ksl` socket where it exists (Linux, Android, Apple, Windows), the portable one otherwise or on request. */
public enum class IoPreference {
    /** The `ksl` socket with batching, GSO/GRO, ECN and DF where the platform has it (Linux, Android; Apple without GSO/GRO; Windows with USO/URO where granted); the portable one elsewhere. */
    Accelerated,

    /**
     * Always the portable socket: NIO on the JVM, `ktor-network` on Native. On the JVM it still loads `ksl` (once per
     * process), to put the socket's DF in probe mode (RFC 9000 sections 14 and 14.2.1); without the library it uses the
     * JDK's `IP_DONTFRAGMENT`, and where DF cannot be set at all (below JDK 19; on Kotlin/Native, whose portable socket has
     * no DF) [DatagramIo.open] throws [QuicException.DontFragmentUnavailable].
     */
    Portable,
}

/** UDP in batches (ADR-0006): the only thing the runtime needs from a platform. */
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
public interface DatagramIo : AutoCloseable {
    /** The local address the socket is bound to, with the port the system picked for port 0. */
    public val localAddress: InetSocketAddress

    /** What the socket can do now; it may lose a feature the kernel refuses at run time (GSO, ECN), and the core adapts per path. */
    public val capabilities: StateFlow<IoCapabilities>

    /** Fills free slots of [into] (from `count`) with received datagrams; suspends until at least one arrived. Throws once closed. */
    public suspend fun receive(into: PacketBatch): Int

    /**
     * Sends the slots of [batch] in order; returns how many left. A result below `batch.count` means the socket refused the
     * rest (a full send buffer): the endpoint counts them in [ConnectionStats.datagramsDroppedSocket] and loss recovery repairs them.
     * A send that throws is counted as losing the whole batch, so an implementation that can should return the slots it sent
     * before a failure instead of throwing.
     */
    public suspend fun send(batch: PacketBatch): Int

    /** Sends what can be sent without suspending; returns the count. */
    public fun trySend(batch: PacketBatch): Int

    /**
     * ECN validation failed on a path that sends through this socket (RFC 9000 section 13.4.2). A socket that marks per socket, like the
     * portable one, clears IP_TOS: every connection on it stops marking. A socket that marks per datagram ignores it: the
     * core already sends NotEct on the failed path, and the other connections keep validating ECN.
     */
    public fun disableEcnMarking() {}

    /**
     * The address family this socket cannot set Don't Fragment for, so nothing of it may go there (no DF, no QUIC: RFC 9000
     * section 14; no DF, no CONNECT-UDP tunnel: RFC 9298 section 3.1), or null when it has DF for every family it reaches: a
     * dual-stack portable socket whose IPv4 or IPv6 half has none, an AF_INET socket (IPv6). A socket without DF at all is
     * never opened ([open] throws [QuicException.DontFragmentUnavailable]). A custom socket overrides it where it applies.
     */
    @ExperimentalKuicksilverApi
    public val noDontFragmentFamily: IpFamily? get() = null

    /** Holds [open], the platform's socket factory. */
    public companion object {
        /**
         * Binds [local] (port 0 picks a free port): the accelerated transport when [prefer] asks for it and the platform has it,
         * the portable one otherwise. No DF, no QUIC (RFC 9000 section 14): throws [QuicException.DontFragmentUnavailable] when
         * the socket cannot set the Don't Fragment bit on any of its traffic.
         */
        public suspend fun open(
            local: InetSocketAddress,
            prefer: IoPreference = IoPreference.Accelerated,
        ): DatagramIo = openDatagramIo(local, prefer, KuicksilverLogger.Default)
    }
}

/** [DatagramIo.open] reporting a fallback to the portable socket to [logger]. */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun openDatagramIo(
    local: InetSocketAddress,
    prefer: IoPreference,
    logger: KuicksilverLogger,
): DatagramIo {
    var refused: Throwable? = null
    if (prefer == IoPreference.Accelerated) {
        KslDatagramIo.open(local, logger = logger, refused = { refused = it })?.let { return it }
    }
    return openPortableDatagramIo(local, refused, logger)
}

/**
 * The portable socket on [local]. [acceleratedRefusal] is why the accelerated socket was not opened, null when it was not
 * tried or gave no reason: where the portable socket cannot carry QUIC (Kotlin/Native), a refused bind (the port in use)
 * is thrown as it is, as the portable socket's own bind would fail elsewhere.
 */
internal expect suspend fun openPortableDatagramIo(
    local: InetSocketAddress,
    acceleratedRefusal: Throwable?,
    logger: KuicksilverLogger = KuicksilverLogger.Default,
): DatagramIo

/**
 * The line a socket opened as two on one port logs ([emit]): IPv6-only and IPv4, because the IPv4 half of a dual-stack socket
 * has no Don't Fragment here (RFC 9000 section 14). [LogLevel.Info] the first time in the process, [LogLevel.Debug] after: a
 * host's DF support does not change while it runs, so one line says it (loops, clients and tunnels open such sockets too).
 */
internal object SplitSocketLog {
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    private val logged = kotlin.concurrent.atomics.AtomicBoolean(false)

    /** The line for a split socket on [host] (numeric text, as the socket reports it) and [port]. */
    fun line(
        host: String,
        port: Int,
    ): String =
        "UDP on ${if (':' in host) "[$host]" else host}:$port uses two sockets (IPv6-only and IPv4) on one port: the IPv4 half " +
            "of a dual-stack socket has no Don't Fragment here (RFC 9000 section 14)"

    /** Logs [line] to [logger]: at Info once per process, at Debug after. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    fun emit(
        logger: KuicksilverLogger,
        host: String,
        port: Int,
    ) {
        val level = if (logged.compareAndSet(false, true)) LogLevel.Info else LogLevel.Debug
        logger.emit(level, message = { line(host, port) })
    }

    /** Tests: the next split socket logs at Info again. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    fun resetForTest() {
        logged.store(false)
    }
}

/** One line to standard error: what [KuicksilverLogger.Stderr] writes. */
internal expect fun printWarning(line: String)

/**
 * Test hook: while true, every wildcard socket of the accelerated transport is opened as two sockets on one port (`ksl`'s
 * KSL_UDP_SPLIT: IPV6_V6ONLY on `::` and AF_INET on 0.0.0.0), the path a host takes whose dual-stack socket gets no Don't
 * Fragment on its IPv4 half (RFC 9000 section 14), and the first such socket after it is set logs its line at Info again
 * ([SplitSocketLog]). No host here refuses that DF; the C tests force the refusal itself. Every platform of the accelerated
 * socket (Linux, Android, Apple, Windows); [datagramIoSplitSupportedForTest] says whether this one has it.
 */
@io.kuicksilver.annotations.InternalKuicksilverApi
@kotlin.concurrent.Volatile
public var datagramIoSplitForTest: Boolean = false
    set(value) {
        if (value) SplitSocketLog.resetForTest()
        field = value
    }

/** Test hook: whether this platform's accelerated transport can open a wildcard as two sockets ([datagramIoSplitForTest]). */
@io.kuicksilver.annotations.InternalKuicksilverApi
public fun datagramIoSplitSupportedForTest(): Boolean {
    if (!io.kuicksilver.tls.KslUdpSocket.supported) return false
    val s =
        io.kuicksilver.tls.KslUdpSocket.openOrNull(
            io.kuicksilver.tls.KslUdpSocket
                .encodeAddress(ByteArray(4), 0),
            io.kuicksilver.tls.KslUdpSocket.SPLIT or io.kuicksilver.tls.KslUdpSocket.DF,
        ) ?: return false
    return try {
        s.grantedFlags and io.kuicksilver.tls.KslUdpSocket.SPLIT != 0
    } finally {
        s.close()
    }
}
