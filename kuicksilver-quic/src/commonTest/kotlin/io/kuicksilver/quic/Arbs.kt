// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.quic.wire.VarInt
import kotlin.random.Random
import kotlin.random.nextInt

/** Generators shared by the property tests of the core: plain draws from a seeded [Random] (see [forAllSeeded]). */
object Arbs {
    fun varint(rnd: Random): Long = rnd.long(0L..VarInt.MAX)

    fun small(rnd: Random): Long = rnd.long(0L..100_000L)

    fun bytes(
        rnd: Random,
        max: Int,
    ): List<Byte> = rnd.bytes(0..max)

    /** One frame of every type of RFC 9000 section 19 (and DATAGRAM, RFC 9221), with values the encoder accepts. */
    fun frame(rnd: Random): TestFrame {
        val b = { rnd.nextBoolean() }
        return when (rnd.nextInt(0..21)) {
            0 -> {
                TestFrame.Padding(rnd.int(1..300))
            }

            1 -> {
                TestFrame.Ping
            }

            2 -> {
                val count = rnd.int(1..8)
                val gaps = List(count) { rnd.long(0L..50L) }
                val lens =
                    List(count) {
                        rnd.long(0L..50L)
                    }
                val ranges = ArrayList<Pair<Long, Long>>()
                var largest = rnd.long(1_000L..1_000_000L)
                for (i in 0 until count) {
                    val smallest =
                        largest - lens[i]
                    ranges += smallest to largest
                    largest = smallest - gaps[i] - 2
                }
                TestFrame.Ack(
                    ranges[0].second,
                    small(rnd),
                    ranges,
                    if (b()) listOf(small(rnd), small(rnd), small(rnd)) else null,
                )
            }

            3 -> {
                TestFrame.ResetStream(small(rnd), varint(rnd), varint(rnd))
            }

            4 -> {
                TestFrame.StopSending(small(rnd), varint(rnd))
            }

            5 -> {
                TestFrame.Crypto(rnd.long(0L..1_000_000L), bytes(rnd, 200))
            }

            6 -> {
                TestFrame.NewToken(rnd.bytes(1..64))
            }

            7 -> {
                TestFrame.Stream(small(rnd), rnd.long(0L..1_000_000L), bytes(rnd, 200), b())
            }

            8 -> {
                TestFrame.MaxData(varint(rnd))
            }

            9 -> {
                TestFrame.MaxStreamData(small(rnd), varint(rnd))
            }

            10 -> {
                TestFrame.MaxStreams(b(), rnd.long(0L..(1L shl 60)))
            }

            11 -> {
                TestFrame.DataBlocked(varint(rnd))
            }

            12 -> {
                TestFrame.StreamDataBlocked(small(rnd), varint(rnd))
            }

            13 -> {
                TestFrame.StreamsBlocked(b(), rnd.long(0L..(1L shl 60)))
            }

            14 -> {
                val seq = small(rnd)
                TestFrame.NewConnectionId(
                    seq,
                    rnd.long(0L..seq),
                    rnd.bytes(1..20),
                    List(16) { rnd.byte() },
                )
            }

            15 -> {
                TestFrame.RetireConnectionId(small(rnd))
            }

            16 -> {
                TestFrame.PathChallenge(rnd.long())
            }

            17 -> {
                TestFrame.PathResponse(rnd.long())
            }

            18 -> {
                val app = b()
                TestFrame.ConnectionClose(app, varint(rnd), if (app) 0 else rnd.long(0L..0x31L), bytes(rnd, 100))
            }

            19 -> {
                TestFrame.HandshakeDone
            }

            20 -> {
                TestFrame.Datagram(bytes(rnd, 200))
            }

            else -> {
                TestFrame.Stream(small(rnd), 0, bytes(rnd, 10), true)
            }
        }
    }
}
