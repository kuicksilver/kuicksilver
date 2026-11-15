// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

/** The WT_CLOSE_SESSION capsule value (draft-ietf-webtrans-http3-16 section 6). */
class WtCloseGapTest {
    /**
     * Section 6: "Application Error Code (32)" -- the whole 32-bit code goes out in network byte order and comes back, also
     * when every one of its four bytes is non-zero.
     */
    @Test fun negative_closeCodeUsesAll32Bits() {
        val v = WtCloseCapsule.encode(0x12345678, "r")
        assertContentEquals(byteArrayOf(0x12, 0x34, 0x56, 0x78, 'r'.code.toByte()), v)
        assertEquals(0x12345678L to "r", WtCloseCapsule.decode(v))
        val max = WtCloseCapsule.encode(0xffffffffL, "")
        assertEquals(0xffffffffL to "", WtCloseCapsule.decode(max))
    }

    /**
     * Section 6: the message's "length MUST NOT exceed 1024 bytes" and "If the Application Error Message exceeds 1024 bytes
     * ... the receiver MUST reset the stream with code H3_MESSAGE_ERROR": exactly 1024 bytes go out whole and are accepted;
     * 1025 are cut when sending and refused when receiving.
     */
    @Test fun negative_reasonOfExactly1024Bytes() {
        val exact = WtCloseCapsule.encode(1, "a".repeat(1024))
        assertEquals(4 + 1024, exact.size)
        assertEquals(1L to "a".repeat(1024), WtCloseCapsule.decode(exact))
        assertEquals(4 + 1024, WtCloseCapsule.encode(1, "a".repeat(1025)).size)
        assertEquals(null, WtCloseCapsule.decode(exact + 'a'.code.toByte()))
    }
}
