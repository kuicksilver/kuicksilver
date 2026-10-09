// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

/** A decoded ACK frame, reused across packets: ranges are (smallest, largest) pairs in descending order, index 0 the highest. */
internal class AckFrameView {
    var largest: Long = 0

    /** Raw ack_delay field (before the exponent is applied). */
    var ackDelay: Long = 0
    var rangeCount: Int = 0
    private var ranges = LongArray(2 * 64) // AckTracker sends at most 64 ranges: never grows in steady state

    /** ECN counts ect0, ect1, ce; null when the frame carried none. */
    var ecn: LongArray? = null
    private val ecnStore = LongArray(3)

    fun smallest(i: Int): Long = ranges[2 * i]

    fun largest(i: Int): Long = ranges[2 * i + 1]

    internal fun reset() {
        rangeCount = 0
        ecn = null
    }

    internal fun addRange(
        smallest: Long,
        largest: Long,
    ) {
        if (2 * rangeCount + 2 > ranges.size) ranges = ranges.copyOf(ranges.size * 2)
        ranges[2 * rangeCount] = smallest
        ranges[2 * rangeCount + 1] = largest
        rangeCount++
    }

    internal fun setEcn(
        ect0: Long,
        ect1: Long,
        ce: Long,
    ) {
        ecnStore[0] = ect0
        ecnStore[1] = ect1
        ecnStore[2] = ce
        ecn = ecnStore
    }
}
