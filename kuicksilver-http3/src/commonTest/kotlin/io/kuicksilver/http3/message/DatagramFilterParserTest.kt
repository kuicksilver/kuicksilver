// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.message

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.VarInt
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A DATAGRAM capsule judged by its Context ID before its value is buffered (RFC 9298 section 5: an oversized UDP payload
 * "MUST abort the corresponding stream", a discarded one is dropped "without buffering the capsule contents"; section 4:
 * unknown Context IDs are dropped).
 */
class DatagramFilterParserTest {
    private fun capsule(
        type: Long,
        payload: ByteArray,
    ) = VarInt.encode(type) + VarInt.encode(payload.size.toLong()) + payload

    private val seen = ArrayList<Pair<Long, Long>>()

    /** Context 0 up to 100 bytes delivered, longer ones skipped, above 1000 aborted; other contexts skipped. */
    private val filter =
        DatagramFilter { ctx, len ->
            seen += ctx to len
            when {
                ctx != 0L -> DatagramVerdict.Skip
                len > 1000 -> DatagramVerdict.Abort
                len > 100 -> DatagramVerdict.Skip
                else -> DatagramVerdict.Deliver
            }
        }

    private fun parser() = CapsuleParser(maxDatagramLength = 65_536, filter = filter)

    @Test fun contextZeroDeliveredWholeOneByteAtATime() {
        val got = ArrayList<ByteArray>()
        val p = parser()
        val bytes = capsule(0, byteArrayOf(0) + "udp".encodeToByteArray()) + capsule(0, byteArrayOf(0))
        for (b in bytes) p.feed(byteArrayOf(b), 0, 1) { _, v -> got += v }
        assertEquals(2, got.size)
        assertContentEquals(byteArrayOf(0) + "udp".encodeToByteArray(), got[0])
        assertContentEquals(byteArrayOf(0), got[1])
        assertEquals(listOf(0L to 3L, 0L to 0L), seen)
    }

    /** A non-minimal Context ID encoding is still Context ID 0 (RFC 9000 section 16 allows any length). */
    @Test fun eightByteContextIdIsRead() {
        val got = ArrayList<ByteArray>()
        val ctx = byteArrayOf(0xc0.toByte(), 0, 0, 0, 0, 0, 0, 0)
        parser().feed(capsule(0, ctx + byteArrayOf(7)).let { it }, 0, 11) { _, v -> got += v }
        assertEquals(listOf(0L to 1L), seen)
        assertEquals(9, got.single().size)
    }

    @Test fun negative_unknownContextSkippedWithoutBuffering() {
        val got = ArrayList<ByteArray>()
        val p = parser()
        val big = VarInt.encode(2) + ByteArray(50_000)
        val bytes = capsule(0, big) + capsule(0, byteArrayOf(0, 1))
        p.feed(bytes, 0, bytes.size) { _, v -> got += v }
        assertEquals(1, got.size)
        assertEquals(listOf(2L to 50_000L, 0L to 1L), seen)
        assertTrue(p.maxBuffered <= 8, "skipped value was buffered: ${p.maxBuffered}")
    }

    @Test fun negative_oversizedContextZeroAbortsBeforeItsBytesArrive() {
        val p = parser()
        val head = VarInt.encode(0) + VarInt.encode(2_000_000) + byteArrayOf(0)
        val e = assertFailsWith<H3ProtocolError> { p.feed(head, 0, head.size) { _, _ -> } }
        assertEquals(Http3ErrorCode.DATAGRAM_ERROR, e.code)
        assertEquals(listOf(0L to 1_999_999L), seen)
    }

    @Test fun skippedByTheFilterIsNotBuffered() {
        val p = parser()
        val bytes = capsule(0, byteArrayOf(0) + ByteArray(500)) + capsule(0, byteArrayOf(0, 9))
        val got = ArrayList<ByteArray>()
        p.feed(bytes, 0, bytes.size) { _, v -> got += v }
        assertContentEquals(byteArrayOf(0, 9), got.single())
        assertTrue(p.maxBuffered <= 8, "skipped value was buffered: ${p.maxBuffered}")
    }

    /** An HTTP datagram too short for its Context ID cannot be read: dropped, never handed to the filter. */
    @Test fun negative_emptyOrTruncatedContextIdIsDropped() {
        val got = ArrayList<ByteArray>()
        val p = parser()
        val bytes = capsule(0, ByteArray(0)) + capsule(0, byteArrayOf(0x40)) + capsule(0, byteArrayOf(0, 5))
        p.feed(bytes, 0, bytes.size) { _, v -> got += v }
        assertContentEquals(byteArrayOf(0, 5), got.single())
        assertEquals(listOf(0L to 1L), seen)
        assertEquals(2, p.skippedDatagrams)
        p.endOfStream()
    }

    @Test fun deliveredValueStillBoundedByMaxDatagramLength() {
        val p = CapsuleParser(maxDatagramLength = 10, filter = { _, _ -> DatagramVerdict.Deliver })
        val got = ArrayList<ByteArray>()
        val bytes = capsule(0, byteArrayOf(0) + ByteArray(20)) + capsule(0, byteArrayOf(0, 1))
        p.feed(bytes, 0, bytes.size) { _, v -> got += v }
        assertEquals(1, got.size)
        assertEquals(1, p.skippedDatagrams)
    }
}
