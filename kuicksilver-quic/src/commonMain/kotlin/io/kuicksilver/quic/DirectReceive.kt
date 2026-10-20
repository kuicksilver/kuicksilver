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
