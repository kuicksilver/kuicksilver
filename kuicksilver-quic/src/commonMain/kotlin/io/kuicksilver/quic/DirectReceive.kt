// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** A socket that can also receive on the calling thread, without suspending (the accelerated `ksl` socket). */
internal interface DirectReceive {
    /**
     * Fills free slots of [into] (from `count`) with the datagrams already queued, or with the first to arrive within [waitMs]
     * milliseconds (0: none waited for) and those queued behind it, blocking the calling thread meanwhile; 0 when none came or
     * the socket is closed.
     */
    fun receiveNow(
        into: PacketBatch,
        waitMs: Int,
    ): Int
}

/**
 * A socket whose `send` never suspends (it is `trySend`) and that reports the datagrams the kernel refused as too large: the
 * accelerated `ksl` socket, and a loop's view of one socket a group shares ([io.kuicksilver.quic.runtime.LoopInbox]). A loop
 * whose sockets are all of this kind flushes without a coroutine frame and takes the EMSGSIZE hints for DPLPMTUD.
 */
internal interface NonSuspendingSend {
    /** The length of the latest datagram the kernel refused as too large since the previous call, or 0; the sender's thread only. */
    fun takeEmsgsize(): Int
}

/** A socket that queues ICMP Packet Too Big messages (Linux and Android with DF): the loop takes them as DPLPMTUD hints. */
internal interface PacketTooBigSource {
    /**
     * Hands [sink] the messages queued since the last call, at most [KslDatagramIo.PTB_PER_DRAIN]: the quoted start of our
     * datagram (valid for [sink]'s call only), its length, the datagram's destination and the MTU the message reports.
     * Spoofable hints the core validates (RFC 8899 section 4.6). One thread at a time.
     */
    fun drainPacketTooBig(sink: (quote: ByteArray, len: Int, dst: io.ktor.network.sockets.InetSocketAddress, mtu: Int) -> Unit)
}
