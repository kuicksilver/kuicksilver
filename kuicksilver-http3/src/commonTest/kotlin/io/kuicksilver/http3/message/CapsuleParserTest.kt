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

class CapsuleParserTest {
    private fun capsule(
        type: Long,
        payload: ByteArray,
    ) = VarInt.encode(type) + VarInt.encode(payload.size.toLong()) + payload

    private fun CapsuleParser.feedAll(
        bytes: ByteArray,
        out: (Long, ByteArray) -> Unit = { _, _ -> },
    ) = feed(bytes, 0, bytes.size, out)

    @Test fun datagramCapsule() {
        val got = ArrayList<Pair<Long, String>>()
        val p = CapsuleParser()
        val bytes = capsule(0x00, "hi".encodeToByteArray()) + capsule(0x00, "there".encodeToByteArray())
        for (b in bytes) p.feed(byteArrayOf(b), 0, 1) { t, payload -> got += t to payload.decodeToString() } // one byte at a time
        assertEquals(listOf(0L to "hi", 0L to "there"), got)
        p.endOfStream()
    }

    @Test fun unknownSkippedStreaming() {
        val got = ArrayList<Long>()
        val p = CapsuleParser()
        val header = VarInt.encode(0x2a) + VarInt.encode(1L shl 20)
        p.feed(header, 0, header.size) { t, _ -> got += t }
        val chunk = ByteArray(16_384)
        repeat(64) { p.feed(chunk, 0, chunk.size) { t, _ -> got += t } } // 1 MiB of an unknown capsule
        val next = capsule(0x00, byteArrayOf(7))
        p.feed(next, 0, next.size) { t, _ -> got += t }
        assertEquals(listOf(0L), got)
        assertTrue(p.maxBuffered <= 16_384 + 16)
    }

    /** A known type other than DATAGRAM longer than the limit is a stream error H3_MESSAGE_ERROR. */
    @Test fun lengthAboveMaxRejected() {
        val p = CapsuleParser(maxCapsuleLength = 1000, known = setOf(0x2843))
        val b = VarInt.encode(0x2843) + VarInt.encode(1001)
        assertEquals(Http3ErrorCode.MESSAGE_ERROR, assertFailsWith<H3ProtocolError> { p.feedAll(b) }.code)
    }

    @Test fun zeroLengthCapsuleDelivered() {
        val got = ArrayList<Pair<Long, ByteArray>>()
        val p = CapsuleParser(known = setOf(0x2843))
        p.feedAll(capsule(0x2843, ByteArray(0))) { t, v -> got += t to v }
        assertEquals(1, got.size)
        assertEquals(0x2843L, got[0].first)
        assertContentEquals(ByteArray(0), got[0].second)
        p.endOfStream()
    }

    /** RFC 9297 section 3.3: a stream that ends inside a capsule (value or header) is a malformed message. */
    @Test fun negative_truncatedCapsuleAtFinIsMessageError() {
        val inValue = CapsuleParser()
        inValue.feedAll(capsule(0x2a, ByteArray(10)).copyOf(7))
        assertEquals(Http3ErrorCode.MESSAGE_ERROR, assertFailsWith<H3ProtocolError> { inValue.endOfStream() }.code)

        val inKnownValue = CapsuleParser()
        inKnownValue.feedAll(capsule(0x00, ByteArray(10)).copyOf(7))
        assertEquals(Http3ErrorCode.MESSAGE_ERROR, assertFailsWith<H3ProtocolError> { inKnownValue.endOfStream() }.code)

        val inHeader = CapsuleParser()
        inHeader.feedAll(byteArrayOf(0x40)) // the first byte of a 2-byte varint type
        assertEquals(Http3ErrorCode.MESSAGE_ERROR, assertFailsWith<H3ProtocolError> { inHeader.endOfStream() }.code)

        val inLength = CapsuleParser()
        inLength.feedAll(byteArrayOf(0x00, 0x40)) // a type, then the first byte of a 2-byte length
        assertEquals(Http3ErrorCode.MESSAGE_ERROR, assertFailsWith<H3ProtocolError> { inLength.endOfStream() }.code)

        val atBoundary = CapsuleParser()
        atBoundary.feedAll(capsule(0x2a, ByteArray(10)) + capsule(0x00, byteArrayOf(1)))
        atBoundary.endOfStream()
        CapsuleParser().endOfStream() // an empty stream is a valid (empty) sequence of capsules
    }

    /**
     * RFC 9297 section 3.5: a DATAGRAM capsule longer than we accept SHOULD be dropped, not treated as an error; it is
     * skipped as it streams by, so a peer announcing a huge length costs no memory.
     */
    @Test fun negative_datagramCapsuleAboveLimitSkipped() {
        val got = ArrayList<ByteArray>()
        val p = CapsuleParser(maxDatagramLength = 1000)
        val header = VarInt.encode(0x00) + VarInt.encode(1_048_576)
        p.feedAll(header) { _, v -> got += v }
        val chunk = ByteArray(16_384)
        repeat(64) { p.feedAll(chunk) { _, v -> got += v } }
        p.feedAll(capsule(0x00, byteArrayOf(7))) { _, v -> got += v }
        assertEquals(1, got.size)
        assertContentEquals(byteArrayOf(7), got[0])
        assertEquals(1L, p.skippedDatagrams)
        assertTrue(p.maxBuffered <= 16_400, "buffered ${p.maxBuffered}")
        p.endOfStream()
    }

    /** A DATAGRAM capsule is bounded by maxDatagramLength alone, so one above maxCapsuleLength but within it is delivered. */
    @Test fun datagramLimitIsIndependentOfCapsuleLimit() {
        val got = ArrayList<ByteArray>()
        val p = CapsuleParser(maxCapsuleLength = 10, maxDatagramLength = 100)
        p.feedAll(capsule(0x00, ByteArray(100) { 1 })) { _, v -> got += v }
        assertEquals(100, got.single().size)
        assertEquals(0L, p.skippedDatagrams)
    }

    /** After a capsule of a terminal type, any byte is a malformed message, even one of a type that would be skipped. */
    @Test fun negative_dataAfterTerminalCapsule() {
        val got = ArrayList<Long>()
        val p = CapsuleParser(known = setOf(0x2843), terminal = setOf(0x2843))
        val bytes = capsule(0x2843, byteArrayOf(1)) + capsule(0x2a, ByteArray(3))
        val e = assertFailsWith<H3ProtocolError> { p.feedAll(bytes) { t, _ -> got += t } }
        assertEquals(Http3ErrorCode.MESSAGE_ERROR, e.code)
        assertEquals(listOf(0x2843L), got) // the terminal capsule itself was delivered

        val oneByOne = CapsuleParser(known = setOf(0x2843), terminal = setOf(0x2843))
        val first = capsule(0x2843, ByteArray(0))
        assertEquals(first.size, oneByOne.feedOne(first + byteArrayOf(0x2a), 0, first.size + 1) { _, _ -> })
        assertFailsWith<H3ProtocolError> { oneByOne.feedAll(byteArrayOf(0x2a)) }
    }

    @Test fun terminalCapsuleThenFinIsClean() {
        val p = CapsuleParser(known = setOf(0x2843), terminal = setOf(0x2843))
        p.feedAll(capsule(0x2a, ByteArray(5)) + capsule(0x2843, byteArrayOf(1)))
        p.endOfStream()
    }
}
