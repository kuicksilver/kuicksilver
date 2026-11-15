// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.wire

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.Arbs
import io.kuicksilver.quic.CollectingHandler
import io.kuicksilver.quic.TestFrame
import io.kuicksilver.quic.forAllSeeded
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
        forAllSeeded(2_000, seed = 0xF4A3EL) { rnd, _ ->
            val f = Arbs.frame(rnd)
            assertEquals(listOf(f), decode(bytesOf(f)).first, "$f")
        }

    @Test fun negative_unknownFrameType() =
        run {
            expectCode(0x07, hex("21"))
            Unit
        }

    /** RFC 9000 section 19.7: "A client MUST treat receipt of a NEW_TOKEN frame with an empty Token field as a connection error of type FRAME_ENCODING_ERROR." */
    @Test fun negative_emptyNewTokenIsFrameEncodingError() {
        expectCode(0x07, hex("07 00"))
        assertEquals(1, decode(hex("07 01 2a")).first.size, "a one-byte token decodes")
    }

    /**
     * RFC 9000 section 19.14: a STREAMS_BLOCKED (0x16 bidi, 0x17 uni) whose Maximum Streams exceeds 2^60 "MUST be treated as a
     * connection error of type STREAM_LIMIT_ERROR or FRAME_ENCODING_ERROR"; we answer FRAME_ENCODING_ERROR. 2^60 itself is valid.
     */
    @Test fun negative_streamsBlockedAbove2Pow60() {
        for (type in listOf("16", "17")) {
            expectCode(0x07, hex("$type d000000000000001")) // 2^60 + 1 as an 8-byte varint
            assertEquals(1, decode(hex("$type d000000000000000")).first.size, "0x$type at 2^60 decodes")
        }
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

    /**
     * RFC 9000 section 19.3.1: "If any computed packet number is negative, an endpoint MUST generate a connection error of type
     * FRAME_ENCODING_ERROR." The second range starts at 8 (largest 10, first range 0, gap 0) and claims 10 packets below it.
     */
    @Test fun negative_ackRangeLengthBelowZeroIsFrameEncodingError() {
        expectCode(0x07, hex("02 0a 00 01 00 00 09"))
        assertEquals(listOf(10L to 10L, 0L to 8L), (decode(hex("02 0a 00 01 00 00 08")).first.single() as TestFrame.Ack).ranges)
    }

    /** RFC 9000 section 13.2.1 / 2: every frame but ACK, PADDING and CONNECTION_CLOSE is ack-eliciting, the stream reset frames too. */
    @Test fun negative_streamResetFramesAreAckEliciting() {
        assertTrue(decode(bytesOf(TestFrame.ResetStream(4, 1, 10))).second, "RESET_STREAM")
        assertTrue(decode(bytesOf(TestFrame.StopSending(4, 1))).second, "STOP_SENDING")
        assertTrue(decode(bytesOf(TestFrame.ResetStreamAt(4, 1, 10, 3))).second, "RESET_STREAM_AT")
    }

    /**
     * The ACK frame's size estimate the packet builder reserves room by (`AckTracker.ackOverhead`) is exactly the size
     * [FrameEncoder.ack] writes, for any ranges, delay and ECN counts: a low estimate would build a packet past its size limit.
     */
    @Test fun negative_ackOverheadIsTheEncodedSize() =
        forAllSeeded(3_000, seed = 0xAC0L) { rnd, _ ->
            val count = if (rnd.nextInt(10) == 0) 64 else rnd.nextInt(1, 6) // 64: the Range Count 63 is the last one-byte varint
            val ranges = LongArray(2 * count)
            var top = rnd.nextLong(1L shl rnd.nextInt(1, 40)) + 4L * count * 70_000
            for (i in 0 until count) {
                val hi = top
                val lo = hi - rnd.nextLong(0, 1L shl rnd.nextInt(0, 16))
                ranges[2 * i] = lo
                ranges[2 * i + 1] = hi
                top = lo - 2 - rnd.nextLong(0, 1L shl rnd.nextInt(0, 16))
            }
            val delay = rnd.nextLong(0, 1L shl rnd.nextInt(0, 40))
            val ecn = if (rnd.nextBoolean()) LongArray(3) { rnd.nextLong(0, 1L shl rnd.nextInt(0, 40)) } else null
            val b = PacketBuffer.allocate(2048)
            try {
                val w = WireWriter(b, 0, b.capacity)
                FrameEncoder.ack(w, ranges, count, delay, ecn)
                assertEquals(
                    w.pos,
                    FrameEncoder.ackOverhead(ranges, count, delay, ecn),
                    "ranges ${ranges.toList()} delay $delay ecn ${ecn?.toList()}",
                )
            } finally {
                b.close()
            }
        }

    /** RFC 9000 section 19.15: a NEW_CONNECTION_ID Length outside 1..20 or a token other than 16 bytes is never written. */
    @Test fun negative_newConnectionIdEncoderRejectsInvalidFields() {
        val b = PacketBuffer.allocate(128)
        try {
            assertFailsWith<IllegalArgumentException> {
                FrameEncoder.newConnectionId(
                    WireWriter(b, 0, b.capacity),
                    1,
                    0,
                    ByteArray(21),
                    ByteArray(16),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                FrameEncoder.newConnectionId(
                    WireWriter(b, 0, b.capacity),
                    1,
                    0,
                    ByteArray(0),
                    ByteArray(16),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                FrameEncoder.newConnectionId(
                    WireWriter(b, 0, b.capacity),
                    1,
                    0,
                    ByteArray(8),
                    ByteArray(15),
                )
            }
        } finally {
            b.close()
        }
    }

    /** RFC 9000 section 2 / 13.2.1: every frame but ACK, PADDING and CONNECTION_CLOSE is ack-eliciting, whatever its type. */
    @Test fun negative_everyOtherFrameTypeIsAckEliciting() =
        forAllSeeded(2_000, seed = 0xE11C1L) { rnd, _ ->
            val f = Arbs.frame(rnd)
            val eliciting = f !is TestFrame.Ack && f !is TestFrame.Padding && f !is TestFrame.ConnectionClose
            assertEquals(eliciting, decode(bytesOf(f)).second, "$f")
        }

    /**
     * RFC 9000 section 19.6: "The largest offset delivered on a stream -- the sum of the offset and data length -- cannot exceed
     * 2^62-1, as it is not possible to provide flow control credit for that data. Receipt of a frame that exceeds this limit MUST
     * be treated as a connection error of type FRAME_ENCODING_ERROR or CRYPTO_BUFFER_EXCEEDED." Section 19.8 says the same of
     * STREAM frames. Exactly 2^62-1 is allowed.
     */
    @Test fun negative_cryptoAndStreamEndAtMostTwoPow62Minus1() {
        expectCode(0x07, hex("06 ff ff ff ff ff ff ff ff 01 61"), PacketType.Initial)
        assertEquals(1, decode(hex("06 ff ff ff ff ff ff ff fe 01 61"), PacketType.Initial).first.size)
        assertEquals(1, decode(hex("0e 04 ff ff ff ff ff ff ff fe 01 61")).first.size)
        expectCode(0x07, hex("0e 04 ff ff ff ff ff ff ff ff 01 61"))
    }

    /** RFC 9000 section 19.11: Maximum Streams "cannot exceed 2^60"; 2^60 itself is a valid MAX_STREAMS value. */
    @Test fun negative_maxStreamsOfExactlyTwoPow60IsValid() {
        assertEquals(1, decode(hex("12 d0 00 00 00 00 00 00 00")).first.size)
        expectCode(0x07, hex("12 d0 00 00 00 00 00 00 01"))
    }

    /** A NEW_CONNECTION_ID frame cut inside its Stateless Reset Token is FRAME_ENCODING_ERROR (RFC 9000 section 19.15). */
    @Test fun negative_truncatedNewConnectionIdIsFrameEncodingError() {
        expectCode(0x07, hex("18 01 00 08 01 02 03 04 05 06 07 08") + ByteArray(10))
    }
}
