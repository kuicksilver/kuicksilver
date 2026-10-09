// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

/** Packet number encoding and decoding (RFC 9000 section 17.1, appendix A.2/A.3). */
internal object PacketNumbers {
    /** Bytes needed to encode [full] given the largest acknowledged packet number ([largestAcked] = -1 before any ACK). */
    fun encodedLength(
        full: Long,
        largestAcked: Long,
    ): Int {
        val unacked = if (largestAcked < 0) full + 1 else full - largestAcked
        var bytes = 1
        while (bytes < 4 && unacked > (1L shl (8 * bytes - 1))) bytes++
        return bytes
    }

    /** Recovers the full packet number from its [truncated] low [bits] given the largest received [largest] (-1 for none). */
    fun decode(
        largest: Long,
        truncated: Long,
        bits: Int,
    ): Long {
        val expected = largest + 1
        val win = 1L shl bits
        val hwin = win / 2
        val mask = win - 1
        val candidate = (expected and mask.inv()) or truncated
        return when {
            candidate <= expected - hwin && candidate < (1L shl 62) - win -> candidate + win
            candidate > expected + hwin && candidate >= win -> candidate - win
            else -> candidate
        }
    }
}
