// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.frame.FrameType
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

/** Application error codes 0..2^32-1 in the HTTP/3 code space (draft-ietf-webtrans-http3-16 section 4.4). */
class WtErrorCodesTest {
    @Test fun edges() {
        assertEquals(0x52e4a40fa8dbL, WtErrorCodes.toHttp3(0))
        assertEquals(0x52e5ac983162L, WtErrorCodes.toHttp3(0xffffffffL))
        assertEquals(0x52e4a40fa8e2L, WtErrorCodes.toHttp3(7))
    }

    @Test fun roundTripAndNoGrease() {
        val rnd = Random(42)
        val ns =
            (0L until 4096L) + List(100_000) { rnd.nextLong(0, 0x1_0000_0000L) } +
                (1L..2000L).flatMap { k -> listOf(k * 0x1e - 1, k * 0x1e, k * 0x1e + 1) } + 0xffffffffL
        for (n in ns) {
            val h = WtErrorCodes.toHttp3(n)
            assertFalse(FrameType.isGrease(h), "toHttp3($n) = 0x${h.toString(16)} is GREASE")
            assertEquals(n, WtErrorCodes.fromHttp3(h), "round trip of $n")
        }
    }

    @Test fun outsideTheRangeIsNull() {
        assertNull(WtErrorCodes.fromHttp3(0x10c))
        assertNull(WtErrorCodes.fromHttp3(0x52e4a40fa8daL))
        assertNull(WtErrorCodes.fromHttp3(0x52e5ac983163L))
        // a GREASE codepoint inside the range names no application code
        val grease = (0x52e4a40fa8dbL..0x52e4a40fa9ffL).first { FrameType.isGrease(it) }
        assertNull(WtErrorCodes.fromHttp3(grease))
    }

    @Test fun negative_applicationCodeAbove32BitsRefused() {
        assertFailsWith<IllegalArgumentException> { WtErrorCodes.toHttp3(0x1_0000_0000L) }
        assertFailsWith<IllegalArgumentException> { WtErrorCodes.toHttp3(-1) }
    }

    @Test fun localReasonTruncatedAtUtf8Boundary() {
        val payload = WtCloseCapsule.encode(42, "a".repeat(1023) + "ё")
        assertEquals(4 + 1023, payload.size)
        assertEquals(42L to "a".repeat(1023), WtCloseCapsule.decode(payload))
    }

    @Test fun negative_closeCapsuleMalformed() {
        assertNull(WtCloseCapsule.decode(byteArrayOf(0, 0, 1)))
        assertNull(WtCloseCapsule.decode(byteArrayOf(0, 0, 0, 1, 0xff.toByte())))
        assertNull(WtCloseCapsule.decode(ByteArray(4 + 1025) { if (it < 4) 0 else 'a'.code.toByte() }))
        assertEquals(0xffffffffL to "", WtCloseCapsule.decode(byteArrayOf(-1, -1, -1, -1)))
    }
}
