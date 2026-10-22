// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kotest.property.Arb
import io.kotest.property.arbitrary.arbitrary
import io.kotest.property.arbitrary.boolean
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.int
import io.kotest.property.arbitrary.list
import io.kotest.property.arbitrary.long
import io.kuicksilver.quic.wire.VarInt

/** Generators shared by the property tests of the core. */
object Arbs {
    fun varint(): Arb<Long> = Arb.long(0L..VarInt.MAX)

    fun small(): Arb<Long> = Arb.long(0L..100_000L)

    fun bytes(max: Int): Arb<List<Byte>> = Arb.list(Arb.byte(), 0..max)

    /** One frame of every type of RFC 9000 section 19 (and DATAGRAM, RFC 9221), with values the encoder accepts. */
    fun frame(): Arb<TestFrame> =
        arbitrary { rs ->
            val b = Arb.boolean()
            when (Arb.int(0..22).bind()) {
                0 -> {
                    TestFrame.Padding(Arb.int(1..300).bind())
                }

                1 -> {
                    TestFrame.Ping
                }

                2 -> {
                    val count = Arb.int(1..8).bind()
                    val gaps = List(count) { Arb.long(0L..50L).bind() }
                    val lens =
                        List(count) {
                            Arb.long(0L..50L).bind()
                        }
                    val ranges = ArrayList<Pair<Long, Long>>()
                    var largest = Arb.long(1_000L..1_000_000L).bind()
                    for (i in 0 until count) {
                        val smallest =
                            largest - lens[i]
                        ranges += smallest to largest
                        largest = smallest - gaps[i] - 2
                    }
                    TestFrame.Ack(
                        ranges[0].second,
                        small().bind(),
                        ranges,
                        if (b.bind()) listOf(small().bind(), small().bind(), small().bind()) else null,
                    )
                }

                3 -> {
                    TestFrame.ResetStream(small().bind(), varint().bind(), varint().bind())
                }

                4 -> {
                    TestFrame.StopSending(small().bind(), varint().bind())
                }

                5 -> {
                    TestFrame.Crypto(Arb.long(0L..1_000_000L).bind(), bytes(200).bind())
                }

                6 -> {
                    TestFrame.NewToken(Arb.list(Arb.byte(), 1..64).bind())
                }

                7 -> {
                    TestFrame.Stream(small().bind(), Arb.long(0L..1_000_000L).bind(), bytes(200).bind(), b.bind())
                }

                8 -> {
                    TestFrame.MaxData(varint().bind())
                }

                9 -> {
                    TestFrame.MaxStreamData(small().bind(), varint().bind())
                }

                10 -> {
                    TestFrame.MaxStreams(b.bind(), Arb.long(0L..(1L shl 60)).bind())
                }

                11 -> {
                    TestFrame.DataBlocked(varint().bind())
                }

                12 -> {
                    TestFrame.StreamDataBlocked(small().bind(), varint().bind())
                }

                13 -> {
                    TestFrame.StreamsBlocked(b.bind(), Arb.long(0L..(1L shl 60)).bind())
                }

                14 -> {
                    val seq = small().bind()
                    TestFrame.NewConnectionId(
                        seq,
                        Arb.long(0L..seq).bind(),
                        Arb.list(Arb.byte(), 1..20).bind(),
                        List(16) { Arb.byte().bind() },
                    )
                }

                15 -> {
                    TestFrame.RetireConnectionId(small().bind())
                }

                16 -> {
                    TestFrame.PathChallenge(Arb.long().bind())
                }

                17 -> {
                    TestFrame.PathResponse(Arb.long().bind())
                }

                18 -> {
                    val app = b.bind()
                    TestFrame.ConnectionClose(app, varint().bind(), if (app) 0 else Arb.long(0L..0x31L).bind(), bytes(100).bind())
                }

                19 -> {
                    TestFrame.HandshakeDone
                }

                20 -> {
                    TestFrame.Datagram(bytes(200).bind())
                }

                22 -> {
                    val finalSize = varint().bind()
                    TestFrame.ResetStreamAt(small().bind(), varint().bind(), finalSize, Arb.long(0L..finalSize).bind())
                }

                else -> {
                    TestFrame.Stream(small().bind(), 0, bytes(10).bind(), true)
                }
            }
        }
}
