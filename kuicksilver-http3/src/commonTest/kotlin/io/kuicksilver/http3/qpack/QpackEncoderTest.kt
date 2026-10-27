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

/** Property test: encoder -> decoder round trip over table size x blocked streams x acknowledgment mode (as ls-qpack does). */
class QpackRoundTripTest {
    private enum class Ack { Immediate, Delayed, Never }

    private val names =
        listOf(
            ":method",
            ":path",
            ":authority",
            "accept",
            "user-agent",
            "x-trace",
            "cookie",
            "content-type",
            "x-custom-${'a'}",
            "cache-control",
        )

    /** 1 to 12 fields of a name from [names] and up to 40 printable ASCII characters (Kotest's default string alphabet). */
    private fun fields(rnd: Random): List<Pair<String, String>> =
        List(rnd.int(1..12)) {
            names.random(rnd) to CharArray(rnd.int(0..40)) { rnd.nextInt(0x20..0x7e).toChar() }.concatToString()
        }

    @Test fun gridRoundTrip() {
        val rs = Random(42)
        for (cap in listOf(0L, 256L, 4096L)) {
            for (blocked in listOf(0, 1, 16)) {
                for (ack in Ack.values()) {
                    val e = QpackEncoder()
                    e.onPeerSettings(cap, blocked.toLong())
                    val d = QpackDecoder(cap, blocked, 65_536)
                    var stream = 0L
                    var pendingAcks = ByteArray(0)
                    repeat(40) { batch ->
                        // five sections in flight at once; their blocks reach the decoder before the encoder stream does
                        val sections =
                            (0 until 5).map {
                                val f =
                                    fields(rs).map { (n, v) ->
                                        n to v.filter { c -> c.code in 0x21..0x7e }
                                    }
                                val id = stream
                                stream +=
                                    4
                                Triple(id, f, e.encode(id, f))
                            }
                        val blockedNow = ArrayList<Triple<Long, List<Pair<String, String>>, ByteArray>>()
                        for (s in sections) {
                            when (val r = d.decode(s.first, s.third)) {
                                is DecodeResult.Decoded -> {
                                    assertEquals(s.second, r.fields)
                                }

                                is DecodeResult.Blocked -> {
                                    d.markBlocked(s.first)
                                    blockedNow += s
                                }

                                DecodeResult.TooLarge -> {
                                    error("too large")
                                }
                            }
                        }
                        val es = e.drainEncoderStream()
                        d.onEncoderStream(es, 0, es.size)
                        for (s in blockedNow) assertEquals(s.second, assertIs<DecodeResult.Decoded>(d.decode(s.first, s.third)).fields)
                        pendingAcks += d.drainDecoderStream()
                        if (ack == Ack.Immediate ||
                            (ack == Ack.Delayed && batch % 3 == 2)
                        ) {
                            e.onDecoderStream(pendingAcks, 0, pendingAcks.size)
                            pendingAcks =
                                ByteArray(0)
                        }
                    }
                }
            }
        }
    }
}
