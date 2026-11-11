// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.qpack

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.int
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class QpackEncoderTest {
    /** Field octets are ISO-8859-1: a wider character is refused, never encoded as its low byte (U+010D as CR). */
    @Test fun negative_charactersAboveLatin1AreRefused() {
        kotlin.test.assertFailsWith<IllegalArgumentException> { QpackEncoder().encode(0, listOf("x-name" to "a\u010Db")) }
    }

    private fun QpackDecoder.feed(b: ByteArray) = onEncoderStream(b, 0, b.size)

    private fun QpackEncoder.feed(b: ByteArray) = onDecoderStream(b, 0, b.size)

    private val req =
        listOf(
            ":method" to "GET",
            ":scheme" to "https",
            ":authority" to "example.com",
            ":path" to "/index.html",
            "user-agent" to "kuicksilver/0.1",
        )

    @Test fun staticOnlyBeforePeerSettings() {
        val e = QpackEncoder()
        val block = e.encode(0, req)
        assertContentEquals(ByteArray(0), e.drainEncoderStream())
        assertEquals(0, block[0].toInt())
        assertEquals(0, block[1].toInt())
        assertEquals(req, assertIs<DecodeResult.Decoded>(QpackDecoder(0, 0, 65_536).decode(0, block)).fields)
    }

    @Test fun dynamicTableUsedAfterPeerSettings() {
        val e = QpackEncoder()
        e.onPeerSettings(4096, 16)
        val d = QpackDecoder(4096, 16, 65_536)
        val first = e.encode(0, req)
        val firstEnc = e.drainEncoderStream()
        d.feed(firstEnc)
        assertEquals(req, assertIs<DecodeResult.Decoded>(d.decode(0, first)).fields)
        e.feed(d.drainDecoderStream())
        val second = e.encode(4, req)
        val secondEnc = e.drainEncoderStream()
        d.feed(secondEnc)
        assertEquals(0, secondEnc.size) // nothing new to insert
        assertTrue(
            second.size + secondEnc.size < (first.size + firstEnc.size) / 2,
            "second ${second.size} vs first ${first.size}+${firstEnc.size}",
        )
        assertEquals(req, assertIs<DecodeResult.Decoded>(d.decode(4, second)).fields)
    }

    /**
     * RFC 9204 section 2.1.3: no instruction without credit for all of it. With none, the section goes without inserts
     * (literals, decodable as they are); with credit for some, only inserts that fit whole are made.
     */
    @Test fun insertsStayWithinTheEncoderStreamCredit() {
        val none = QpackEncoder().also { it.onPeerSettings(4096, 16) }
        none.drainEncoderStream() // Set Dynamic Table Capacity
        val block = none.encode(0, req, instructionBudget = 0)
        assertContentEquals(ByteArray(0), none.drainEncoderStream())
        assertEquals(req, assertIs<DecodeResult.Decoded>(QpackDecoder(4096, 16, 65_536).decode(0, block)).fields)
        val full = QpackEncoder().also { it.onPeerSettings(4096, 16) }
        full.drainEncoderStream()
        full.encode(0, req)
        val all = full.drainEncoderStream().size
        assertTrue(all > 20, "the unbounded encoder inserts")
        for (budget in listOf(1L, all / 2L, all - 1L)) {
            val some = QpackEncoder().also { it.onPeerSettings(4096, 16) }
            val d = QpackDecoder(4096, 16, 65_536)
            d.feed(some.drainEncoderStream()) // Set Dynamic Table Capacity, sent with the SETTINGS
            val b = some.encode(0, req, instructionBudget = budget)
            val ins = some.drainEncoderStream()
            assertTrue(ins.size <= budget, "$budget: ${ins.size} bytes of instructions")
            d.feed(ins)
            assertEquals(req, assertIs<DecodeResult.Decoded>(d.decode(0, b)).fields)
        }
    }

    @Test fun neverIndexSensitive() {
        val e = QpackEncoder()
        e.onPeerSettings(4096, 16)
        val d = QpackDecoder(4096, 16, 65_536)
        val f = listOf("authorization" to "Bearer secret", "cookie" to "a=b", "set-cookie" to "c=d")
        val b = e.encode(0, f)
        d.feed(e.drainEncoderStream())
        assertEquals(0, e.insertCount)
        assertEquals(f, assertIs<DecodeResult.Decoded>(d.decode(0, b)).fields)
        // every line is a literal with the N bit: 01N1xxxx (static name ref) or 001N... (literal name)
        assertTrue(e.lastNeverIndexed == 3)
    }

    @Test fun blockedBudgetIsMinOfPeerAnd100() {
        val e = QpackEncoder()
        e.onPeerSettings(4096, 1000)
        assertEquals(100, e.maxBlockedStreams)
        val e2 = QpackEncoder(maxCapacity = 1024)
        e2.onPeerSettings(4096, 3)
        assertEquals(3, e2.maxBlockedStreams)
        assertEquals(1024, e2.capacity)
    }

    @Test fun doesNotEvictUnacknowledged() {
        val e = QpackEncoder()
        e.onPeerSettings(120, 16)
        val d = QpackDecoder(120, 16, 65_536)
        // 58 bytes each: two fit, the third would have to evict the first, which is neither acknowledged nor unreferenced
        e.encode(0, listOf("x-one" to "a".repeat(21)))
        e.encode(4, listOf("x-two" to "b".repeat(21)))
        e.encode(
            8,
            listOf("x-thr" to "c".repeat(21)),
        )
        d.feed(e.drainEncoderStream())
        assertEquals(2, d.insertCount)
    }

    @Test fun decoderStreamUnknownAckIsError() {
        val e = QpackEncoder()
        e.onPeerSettings(4096, 16)
        assertEquals(Http3ErrorCode.QPACK_DECODER_STREAM_ERROR, assertFailsWith<QpackError> { e.feed(byteArrayOf(0x84.toByte())) }.code)
        assertEquals(
            Http3ErrorCode.QPACK_DECODER_STREAM_ERROR,
            assertFailsWith<QpackError> {
                e.feed(byteArrayOf(0x05))
            }.code,
        ) // increment past the inserts
    }

    /** RFC 9204 section 4.4.3: an Insert Count Increment of zero is QPACK_DECODER_STREAM_ERROR. */
    @Test fun zeroInsertCountIncrementIsError() {
        val e = QpackEncoder()
        e.onPeerSettings(4096, 16)
        assertEquals(Http3ErrorCode.QPACK_DECODER_STREAM_ERROR, assertFailsWith<QpackError> { e.feed(byteArrayOf(0x00)) }.code)
    }

    /** Encoder state per stream is capped. A peer that acknowledges inserts but never a section would otherwise grow it without bound. */
    @Test fun negative_qpackUnackedSectionsCapped() {
        val e = QpackEncoder()
        e.onPeerSettings(4096, 16)
        val d = QpackDecoder(4096, 16, 65_536)
        for (i in 0 until 3000) {
            val block = e.encode(4L * i, req)
            d.feed(e.drainEncoderStream())
            if (i == 0) {
                assertIs<DecodeResult.Decoded>(d.decode(0, block))
                e.feed(d.drainDecoderStream())
            } // one Insert Count Increment, never a Section Acknowledgment
            assertTrue(
                e.outstandingSections <= QpackEncoder.MAX_OUTSTANDING_SECTIONS,
                "outstanding ${e.outstandingSections} after $i encodes",
            )
        }
        assertEquals(req, assertIs<DecodeResult.Decoded>(d.decode(4L * 2999, e.encode(4L * 2999, req))).fields)
    }
}
