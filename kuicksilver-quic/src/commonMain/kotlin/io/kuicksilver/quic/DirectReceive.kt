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
