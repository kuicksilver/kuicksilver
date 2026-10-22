// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kotest.property.checkAll
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.Arbs
import io.kuicksilver.quic.CollectingHandler
import io.kuicksilver.quic.TestFrame
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FrameCodecTest {
    private fun encode(
        w: WireWriter,
        f: TestFrame,
    ) {
        when (f) {
            is TestFrame.Padding -> {
                FrameEncoder.padding(w, f.count)
            }

            TestFrame.Ping -> {
                FrameEncoder.ping(w)
            }

            is TestFrame.Ack -> {
                val ranges = LongArray(f.ranges.size * 2)
                f.ranges.forEachIndexed { i, (s, l) ->
                    ranges[2 * i] = s
                    ranges[
                        2 *
                            i +
                            1,
                    ] =
                        l
                }
                FrameEncoder.ack(w, ranges, f.ranges.size, f.ackDelay, f.ecn?.toLongArray())
            }

            is TestFrame.ResetStream -> {
                FrameEncoder.resetStream(w, f.id, f.code, f.finalSize)
            }

            is TestFrame.StopSending -> {
                FrameEncoder.stopSending(w, f.id, f.code)
            }

            is TestFrame.ResetStreamAt -> {
                FrameEncoder.resetStreamAt(w, f.id, f.code, f.finalSize, f.reliableSize)
            }

            is TestFrame.Crypto -> {
                withBuf(f.data) { b -> FrameEncoder.crypto(w, f.offset, b, 0, f.data.size) }
            }

            is TestFrame.NewToken -> {
                withBuf(f.token) { b -> FrameEncoder.newToken(w, b, 0, f.token.size) }
            }

            is TestFrame.Stream -> {
                withBuf(f.data) { b -> FrameEncoder.stream(w, f.id, f.offset, b, 0, f.data.size, f.fin, withLength = true) }
            }

            is TestFrame.MaxData -> {
                FrameEncoder.maxData(w, f.max)
            }

            is TestFrame.MaxStreamData -> {
                FrameEncoder.maxStreamData(w, f.id, f.max)
            }

            is TestFrame.MaxStreams -> {
                FrameEncoder.maxStreams(w, f.bidi, f.max)
            }

            is TestFrame.DataBlocked -> {
                FrameEncoder.dataBlocked(w, f.limit)
            }

            is TestFrame.StreamDataBlocked -> {
                FrameEncoder.streamDataBlocked(w, f.id, f.limit)
            }

            is TestFrame.StreamsBlocked -> {
                FrameEncoder.streamsBlocked(w, f.bidi, f.limit)
            }

            is TestFrame.NewConnectionId -> {
                FrameEncoder.newConnectionId(w, f.seq, f.retirePriorTo, f.cid.toByteArray(), f.token.toByteArray())
            }

            is TestFrame.RetireConnectionId -> {
                FrameEncoder.retireConnectionId(w, f.seq)
            }

            is TestFrame.PathChallenge -> {
                FrameEncoder.pathChallenge(w, f.data)
            }

            is TestFrame.PathResponse -> {
                FrameEncoder.pathResponse(w, f.data)
            }

            is TestFrame.ConnectionClose -> {
                FrameEncoder.connectionClose(w, f.application, f.code, f.frameType, f.reason.toByteArray())
            }

            TestFrame.HandshakeDone -> {
                FrameEncoder.handshakeDone(w)
            }

            is TestFrame.Datagram -> {
                withBuf(f.data) { b -> FrameEncoder.datagram(w, b, 0, f.data.size, withLength = true) }
            }
        }
    }

    private inline fun withBuf(
        data: List<Byte>,
        block: (PacketBuffer) -> Unit,
    ) {
        val b = PacketBuffer.of(data.toByteArray() + ByteArray(1))
        try {
            block(b)
        } finally {
            b.close()
        }
    }

    private fun decode(
        bytes: ByteArray,
        type: PacketType = PacketType.OneRtt,
    ): Pair<List<TestFrame>, Boolean> {
        val b = PacketBuffer.of(bytes)
        try {
            val h = CollectingHandler()
            val el = FrameDecoder.decode(WireReader(b, 0, bytes.size), type, h)
            return h.frames to
                el
        } finally {
            b.close()
        }
    }

    private fun bytesOf(vararg frames: TestFrame): ByteArray {
        val b = PacketBuffer.allocate(4096)
        try {
            val w = WireWriter(b, 0, b.capacity)
            frames.forEach { encode(w, it) }
            return ByteArray(w.pos).also { b.copyTo(it, 0, 0, w.pos) }
        } finally {
            b.close()
        }
    }

    private fun hex(s: String) =
        s
            .replace(" ", "")
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    private fun expectCode(
        code: Long,
        bytes: ByteArray,
        type: PacketType = PacketType.OneRtt,
    ): QuicWireException {
        val e = assertFailsWith<QuicWireException> { decode(bytes, type) }
        assertEquals(code, e.code, "code")
        return e
    }

    /** draft-ietf-quic-reliable-stream-reset section 4: type 0x24, then Stream ID, Error Code, Final Size, Reliable Size. */
    @Test fun resetStreamAtRoundTrips() {
        val f = TestFrame.ResetStreamAt(4, 0x52e4a40fa8e2, 1000, 3)
        val bytes = bytesOf(f)
        assertEquals(0x24, bytes[0].toInt())
        assertEquals(listOf<TestFrame>(f), decode(bytes).first)
        assertEquals(listOf<TestFrame>(f), decode(bytes, PacketType.ZeroRtt).first)
        expectCode(0x0a, bytes, PacketType.Handshake) // PROTOCOL_VIOLATION: not in Initial or Handshake packets
    }

    /** Section 4: a Reliable Size above the Final Size is FRAME_ENCODING_ERROR. */
    @Test fun negative_resetStreamAtReliableSizeAboveFinalIsError() {
        expectCode(0x07, bytesOf(TestFrame.ResetStreamAt(4, 1, 10, 11)))
    }

    @Test fun everyFrameTypeRoundTrips() =
        runTest {
            checkAll(2_000, Arbs.frame()) { f -> assertEquals(listOf(f), decode(bytesOf(f)).first) }
        }

    @Test fun negative_unknownFrameType() =
        run {
            expectCode(0x07, hex("21"))
            Unit
        }

    @Test fun frameNotAllowedInPacketTypeIsProtocolViolation() {
        expectCode(0x0a, bytesOf(TestFrame.Stream(0, 0, listOf(1), true)), PacketType.Initial)
        expectCode(0x0a, bytesOf(TestFrame.HandshakeDone), PacketType.Handshake)
        expectCode(0x0a, bytesOf(TestFrame.NewToken(listOf(1))), PacketType.Handshake)
        expectCode(0x0a, bytesOf(TestFrame.Ack(1, 0, listOf(0L to 1L), null)), PacketType.ZeroRtt)
        expectCode(0x0a, bytesOf(TestFrame.ConnectionClose(true, 0, 0, emptyList())), PacketType.Initial)
        assertEquals(1, decode(bytesOf(TestFrame.Crypto(0, listOf(1))), PacketType.Handshake).first.size)
    }

    @Test fun emptyPayloadIsProtocolViolation() =
        run {
            expectCode(0x0a, ByteArray(0))
            Unit
        }

    @Test fun streamOffsetPlusLengthAbove2Pow62IsFrameEncodingError() =
        run {
            expectCode(
                0x07,
                hex("0e 04") + hex("ffffffffffffffff") + hex("01") + hex("00"),
            )
            ; Unit
        } // STREAM with OFF|LEN: id 4, offset 2^62-1, length 1

    @Test fun newConnectionIdLength0Or21IsFrameEncodingError() {
        expectCode(0x07, hex("18 01 00 00") + ByteArray(16))
        expectCode(0x07, hex("18 01 00 15") + ByteArray(21) + ByteArray(16))
    }

    @Test fun retirePriorToAboveSequenceIsFrameEncodingError() =
        run {
            expectCode(0x07, hex("18 01 02 08") + ByteArray(8) + ByteArray(16))
            Unit
        }

    @Test fun ackRangeBelowZeroIsFrameEncodingError() =
        run {
            expectCode(0x07, hex("02 05 00 00 09"))
            Unit
        } // largest 5, first range 9

    @Test fun maxStreamsAbove2Pow60IsFrameEncodingError() =
        run {
            expectCode(0x07, hex("12") + hex("d000000000000001"))
            Unit
        } // 2^60 + 1

    @Test fun connectionCloseReasonBeyondPayloadIsFrameEncodingError() =
        run {
            expectCode(0x07, hex("1c 00 00 05 41"))
            Unit
        }

    @Test fun paddingRunReportedOnce() {
        val (frames, el) = decode(ByteArray(1000))
        assertEquals(listOf<TestFrame>(TestFrame.Padding(1000)), frames)
        assertFalse(el)
    }

    @Test fun ackElicitingFlag() {
        assertFalse(
            decode(
                bytesOf(
                    TestFrame.Ack(3, 0, listOf(0L to 3L), null),
                    TestFrame.Padding(5),
                    TestFrame.ConnectionClose(false, 0, 0, emptyList()),
                ),
            ).second,
        )
        assertTrue(decode(bytesOf(TestFrame.Ack(3, 0, listOf(0L to 3L), null), TestFrame.Ping)).second)
        assertTrue(decode(bytesOf(TestFrame.Stream(4, 0, emptyList(), true))).second)
    }

    @Test fun truncatedStreamFrameIsFrameEncodingError() =
        run {
            expectCode(0x07, hex("0a 04 10") + ByteArray(5))
            Unit
        }
}
