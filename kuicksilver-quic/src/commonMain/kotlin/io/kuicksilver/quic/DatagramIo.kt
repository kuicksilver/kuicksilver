// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
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
        ): DatagramIo = openDatagramIo(local, prefer, KuicksilverLogger.Stderr)
    }
}

/** [DatagramIo.open] reporting a fallback to the portable socket to [logger]. */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun openDatagramIo(
    local: InetSocketAddress,
    prefer: IoPreference,
    logger: KuicksilverLogger,
): DatagramIo =
    (if (prefer == IoPreference.Accelerated) KslDatagramIo.open(local, logger = logger) else null) ?: openPortableDatagramIo(local, true)

/**
 * A UDP socket for traffic that is not QUIC, such as a CONNECT-UDP proxy's sockets towards its targets: RFC 9298 section 3.1
 * asks DF "if possible" there ("In IPv4, the Don't Fragment (DF) bit MUST be set, if possible, to prevent fragmentation on
 * the path"; the proxy itself keeps to its link MTU, "UDP proxies MUST NOT introduce fragmentation at the IP layer").
 * Like [DatagramIo.open], with DF set in probe mode, else DO mode, wherever the socket can; unlike it, a socket without
 * DF (the JVM without `ksl` below JDK 19, the Kotlin/Native portable socket, a system refusing both modes) is not refused,
 * and no send is refused for its address family. QUIC endpoints keep [DatagramIo.open]'s rule: no DF, no QUIC.
 */
@InternalKuicksilverApi
public suspend fun openDatagramIoDfIfPossible(
    local: InetSocketAddress,
    prefer: IoPreference = IoPreference.Accelerated,
): DatagramIo =
    (if (prefer == IoPreference.Accelerated) KslDatagramIo.open(local, requireDf = false) else null)
        ?: openPortableDatagramIo(local, false)

/** The portable socket: [strictDf] refuses one without DF ([QuicException.DontFragmentUnavailable]: QUIC), else DF if possible. */
internal expect suspend fun openPortableDatagramIo(
    local: InetSocketAddress,
    strictDf: Boolean,
): DatagramIo

/** One line to standard error: what [KuicksilverLogger.Stderr], the default logger, writes. */
internal expect fun printWarning(line: String)
