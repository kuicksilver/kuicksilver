// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kotest.property.Arb
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.long
import io.kotest.property.checkAll
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PacketNumbersTest {
    @Test fun rfc9000A3DecodeSample() = assertEquals(0xa82f9b32L, PacketNumbers.decode(0xa82f30eaL, 0x9b32L, 16))

    @Test fun rfc9000A2EncodeSamples() {
        assertEquals(2, PacketNumbers.encodedLength(0xac5c02L, 0xabe8b3L))
        assertEquals(3, PacketNumbers.encodedLength(0xace8feL, 0xabe8b3L))
    }

    @Test fun noAckYetCountsFromZero() {
        assertEquals(1, PacketNumbers.encodedLength(0, -1))
        assertEquals(1, PacketNumbers.encodedLength(100, -1))
        assertEquals(2, PacketNumbers.encodedLength(200, -1))
        assertEquals(
            4,
            PacketNumbers.encodedLength(1L shl 30, -1),
        )
    }

    @Test fun encodeDecodeRoundTrip() =
        runTest {
            checkAll(5_000, Arb.long(0L..(1L shl 40)), Arb.int(1..4)) { largest, bytes ->
                val bits = bytes * 8
                val half = 1L shl (bits - 1)
                // RFC 9000 appendix A.3: the window is (expected - half, expected + half] with expected = largest + 1
                val lo = maxOf(0L, largest + 2 - half)
                val hi = minOf(VarInt.MAX, largest + 1 + half)
                for (pn in listOf(lo, largest + 1, hi, (lo + hi) / 2)) {
                    if (pn in lo..hi) {
                        val truncated = pn and ((1L shl bits) - 1)
                        assertEquals(pn, PacketNumbers.decode(largest, truncated, bits), "largest=$largest bits=$bits pn=$pn")
                    }
                }
            }
        }

    @Test fun decodeNeverExceeds2Pow62() {
        assertTrue(PacketNumbers.decode(VarInt.MAX - 1, (VarInt.MAX + 1) and 0xff, 8) <= VarInt.MAX)
    }
}
