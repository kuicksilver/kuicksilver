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

                                is DecodeResult.TooLarge -> {
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
