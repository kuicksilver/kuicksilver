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
public class IoCapabilities(
    public val ecnSend: Boolean,
    public val ecnReceive: Boolean,
    public val gsoMaxSegments: Int,
    public val gro: Boolean,
    public val df: Boolean,
    public val batch: Int,
) {
    /** Holds [Portable]: no accelerated feature (one datagram per call; no ECN, GSO, GRO or DF), what a plain UDP socket offers. */
    public companion object {
        public val Portable: IoCapabilities = IoCapabilities(false, false, 1, false, false, 1)
    }
}

/** Which implementation [DatagramIo.open] prefers: the accelerated `ksl` socket where it exists (Linux, Android), the portable one otherwise or on request. */
public enum class IoPreference {
    /** The `ksl` socket with batching, GSO/GRO, ECN and DF where the platform has it (Linux, Android); the portable one elsewhere. */
    Accelerated,

    /** Always the portable socket: NIO on the JVM, `ktor-network` on Native. */
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
        /** Binds [local] (port 0 picks a free port): the accelerated transport when [prefer] asks for it and the platform has it, the portable one otherwise. */
        public suspend fun open(
            local: InetSocketAddress,
            prefer: IoPreference = IoPreference.Accelerated,
        ): DatagramIo = (if (prefer == IoPreference.Accelerated) KslDatagramIo.open(local) else null) ?: openPortableDatagramIo(local)
    }
}

internal expect suspend fun openPortableDatagramIo(local: InetSocketAddress): DatagramIo
