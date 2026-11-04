// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.frame

import io.kuicksilver.http2.Http2ErrorCode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FrameCodecTest {
    /** Feeds [bytes] in pieces of [chunk] and collects every frame. */
    private fun decodeAll(
        bytes: ByteArray,
        decoder: FrameDecoder = FrameDecoder(),
        chunk: Int = bytes.size,
    ): List<Frame> {
        val out = mutableListOf<Frame>()
        var off = 0
        while (off < bytes.size) {
            val n = minOf(chunk, bytes.size - off)
            var used = 0
            while (used < n) {
                used += decoder.feed(bytes, off + used, n - used)
                decoder.next()?.let { out += it }
            }
            off += n
        }
        decoder.next()?.let { out += it }
        return out
    }

    private fun one(bytes: ByteArray): Frame = decodeAll(bytes).single()

    private fun connError(
        code: Http2ErrorCode,
        bytes: ByteArray,
    ) {
        val e = assertFailsWith<H2ConnectionError> { decodeAll(bytes) }
        assertEquals(code, e.code, e.message)
    }

    @Test
    fun roundTripEveryType() {
        val payload = "hello".encodeToByteArray()
        val frames =
            listOf(
                FrameEncoder.data(1, payload, 0, payload.size, endStream = true),
                FrameEncoder.headers(3, byteArrayOf(0x82.toByte()), endStream = false, endHeaders = false, dependency = 1),
                FrameEncoder.priority(5, 3),
                FrameEncoder.rstStream(7, 0x8),
                FrameEncoder.settings(intArrayOf(SettingId.ENABLE_PUSH, SettingId.INITIAL_WINDOW_SIZE), longArrayOf(0, 1_000_000)),
                FrameEncoder.settingsAck(),
                FrameEncoder.pushPromise(1, 2, byteArrayOf(0x88.toByte()), endHeaders = true),
                FrameEncoder.ping(ack = true, payload = 0x0102030405060708),
                FrameEncoder.goAway(9, 0xb, "calm".encodeToByteArray()),
                FrameEncoder.windowUpdate(0, 65_535),
                FrameEncoder.continuation(3, byteArrayOf(0x84.toByte()), endHeaders = true),
            )
        // one byte at a time: the decoder is incremental
        val decoded = decodeAll(frames.reduce { a, b -> a + b }, chunk = 1)
        assertEquals(frames.size, decoded.size)
        assertIs<Frame.Data>(decoded[0]).let {
            assertEquals(1, it.streamId)
            assertContentEquals(payload, it.data)
            assertTrue(it.endStream)
            assertEquals(5, it.flowLength)
        }
        assertIs<Frame.Headers>(decoded[1]).let {
            assertEquals(3, it.streamId)
            assertContentEquals(byteArrayOf(0x82.toByte()), it.fragment)
            assertFalse(it.endStream)
            assertFalse(it.endHeaders)
            assertEquals(1, it.dependency)
        }
        assertIs<Frame.Priority>(decoded[2]).let { assertEquals(5 to 3, it.streamId to it.dependency) }
        assertIs<Frame.RstStream>(decoded[3]).let { assertEquals(7 to 8L, it.streamId to it.errorCode) }
        assertIs<Frame.Settings>(decoded[4]).let {
            assertFalse(it.ack)
            assertContentEquals(intArrayOf(2, 4), it.ids)
            assertContentEquals(longArrayOf(0, 1_000_000), it.values)
        }
        assertTrue(assertIs<Frame.Settings>(decoded[5]).ack)
        assertIs<Frame.PushPromise>(decoded[6]).let {
            assertEquals(1 to 2, it.streamId to it.promisedStreamId)
            assertTrue(it.endHeaders)
        }
        assertIs<Frame.Ping>(decoded[7]).let {
            assertTrue(it.ack)
            assertEquals(0x0102030405060708, it.payload)
        }
        assertIs<Frame.GoAway>(decoded[8]).let {
            assertEquals(9, it.lastStreamId)
            assertEquals(0xbL, it.errorCode)
            assertEquals("calm", it.debug.decodeToString())
        }
        assertIs<Frame.WindowUpdate>(decoded[9]).let { assertEquals(0 to 65_535, it.streamId to it.increment) }
        assertIs<Frame.Continuation>(decoded[10]).let { assertTrue(it.endHeaders) }
    }

    @Test
    fun paddingStripped() {
        val d = assertIs<Frame.Data>(one(FrameEncoder.data(1, byteArrayOf(1, 2, 3), 0, 3, endStream = false, padLength = 10)))
        assertContentEquals(byteArrayOf(1, 2, 3), d.data)
        assertEquals(1 + 3 + 10, d.flowLength) // the pad length byte and the padding count toward flow control (section 6.1)
        val h =
            assertIs<Frame.Headers>(
                one(FrameEncoder.headers(1, byteArrayOf(9, 9), endStream = true, endHeaders = true, dependency = 0, padLength = 4)),
            )
        assertContentEquals(byteArrayOf(9, 9), h.fragment)
        assertEquals(0, h.dependency)
        // a padded DATA frame with no content: only the pad length byte
        assertEquals(0, assertIs<Frame.Data>(one(FrameEncoder.raw(FrameType.DATA, FrameFlags.PADDED, 1, byteArrayOf(0)))).data.size)
    }

    @Test
    fun negative_padLengthBeyondPayloadIsProtocolError() {
        // pad length 3 in a 3-byte payload: the padding is the length of the payload or more (section 6.1)
        connError(Http2ErrorCode.PROTOCOL_ERROR, FrameEncoder.raw(FrameType.DATA, FrameFlags.PADDED, 1, byteArrayOf(3, 0, 0)))
        // HEADERS: the padding does not fit after the priority fields (section 6.2)
        connError(
            Http2ErrorCode.PROTOCOL_ERROR,
            FrameEncoder.raw(
                FrameType.HEADERS,
                FrameFlags.PADDED or FrameFlags.PRIORITY or FrameFlags.END_HEADERS,
                1,
                byteArrayOf(1, 0, 0, 0, 0, 0),
            ),
        )
        // PUSH_PROMISE: padding beyond the promised stream ID (section 6.6)
        connError(Http2ErrorCode.PROTOCOL_ERROR, FrameEncoder.raw(FrameType.PUSH_PROMISE, FrameFlags.PADDED, 1, byteArrayOf(2, 0, 0, 0, 2)))
        // PADDED without room for the pad length byte: too short for its mandatory fields (section 4.2)
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.DATA, FrameFlags.PADDED, 1, ByteArray(0)))
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.HEADERS, FrameFlags.PRIORITY, 1, ByteArray(4)))
    }

    @Test
    fun negative_frameAboveMaxFrameSizeIsFrameSizeError() {
        val d = FrameDecoder(16_384)
        val header = byteArrayOf(0x00, 0x40, 0x01, FrameType.DATA.toByte(), 0, 0, 0, 0, 1) // 16 385 bytes declared
        val e = assertFailsWith<H2ConnectionError> { d.feed(header, 0, header.size) }
        assertEquals(Http2ErrorCode.FRAME_SIZE_ERROR, e.code)
        assertEquals(0, d.allocatedBytes) // nothing beyond the 9-byte header was buffered
        // exactly the limit is fine
        val ok = FrameDecoder(16_384)
        val frame = FrameEncoder.data(1, ByteArray(16_384), 0, 16_384, endStream = false)
        assertEquals(16_384, assertIs<Frame.Data>(decodeAll(frame, ok).single()).data.size)
    }

    @Test
    fun negative_settingsLengthNotMultipleOfSixIsFrameSizeError() {
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.SETTINGS, 0, 0, ByteArray(7)))
        // an ACK with a payload (section 6.5)
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.SETTINGS, FrameFlags.ACK, 0, ByteArray(6)))
    }

    @Test
    fun negative_pingLengthNotEightIsFrameSizeError() {
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.PING, 0, 0, ByteArray(7)))
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.PING, 0, 0, ByteArray(9)))
    }

    @Test
    fun negative_windowUpdateLengthNotFour() {
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.WINDOW_UPDATE, 0, 1, ByteArray(3)))
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.RST_STREAM, 0, 1, ByteArray(5))) // section 6.4
        connError(Http2ErrorCode.FRAME_SIZE_ERROR, FrameEncoder.raw(FrameType.GOAWAY, 0, 0, ByteArray(7))) // section 6.8
        // PRIORITY of another length is a stream error (section 6.3), and the decoder stays in sync after it
        val d = FrameDecoder()
        val bytes = FrameEncoder.raw(FrameType.PRIORITY, 0, 3, ByteArray(4)) + FrameEncoder.ping(false, 1)
        val e = assertFailsWith<H2StreamError> { decodeAll(bytes, d) }
        assertEquals(3 to Http2ErrorCode.FRAME_SIZE_ERROR, e.streamId to e.code)
        assertIs<Frame.Ping>(decodeAll(bytes.copyOfRange(13, bytes.size), d).single())
    }

    @Test
    fun negative_streamIdOnConnectionFrameIsProtocolError() {
        connError(Http2ErrorCode.PROTOCOL_ERROR, FrameEncoder.raw(FrameType.SETTINGS, 0, 1, ByteArray(0)))
        connError(Http2ErrorCode.PROTOCOL_ERROR, FrameEncoder.raw(FrameType.PING, 0, 1, ByteArray(8)))
        connError(Http2ErrorCode.PROTOCOL_ERROR, FrameEncoder.raw(FrameType.GOAWAY, 0, 1, ByteArray(8)))
    }

    @Test
    fun negative_dataOnStreamZero() {
        connError(Http2ErrorCode.PROTOCOL_ERROR, FrameEncoder.data(0, ByteArray(1), 0, 1, endStream = false))
        // and every other stream-bound type (sections 6.2-6.4, 6.6, 6.10)
        for (t in listOf(FrameType.HEADERS, FrameType.PRIORITY, FrameType.RST_STREAM, FrameType.PUSH_PROMISE, FrameType.CONTINUATION)) {
            connError(Http2ErrorCode.PROTOCOL_ERROR, FrameEncoder.raw(t, 0, 0, ByteArray(if (t == FrameType.PRIORITY) 5 else 4)))
        }
    }

    @Test
    fun unknownFrameTypeSkippedStreaming() {
        val mib = 1 shl 20
        val d = FrameDecoder(mib)
        val header = byteArrayOf(0x10, 0, 0, 0xfa.toByte(), 0x5, 0, 0, 0, 7)
        assertEquals(9, d.feed(header, 0, 9))
        assertNull(d.next())
        val piece = ByteArray(4096)
        var left = mib
        while (left > 0) {
            val n = minOf(piece.size, left)
            assertEquals(n, d.feed(piece, 0, n))
            left -= n
            if (left > 0) assertNull(d.next())
        }
        val u = assertIs<Frame.Unknown>(d.next())
        assertEquals(0xfa to mib, u.type to u.length)
        assertEquals(7, u.streamId)
        assertEquals(0, d.allocatedBytes) // streamed past, never buffered
        // the next frame decodes normally
        assertIs<Frame.Ping>(decodeAll(FrameEncoder.ping(false, 5), d).single())
    }

    @Test
    fun reservedBitIgnored() {
        val f = FrameEncoder.windowUpdate(5, 100)
        f[5] = (f[5].toInt() or 0x80).toByte() // R bit of the stream identifier
        f[9] = (f[9].toInt() or 0x80).toByte() // R bit of the increment
        val w = assertIs<Frame.WindowUpdate>(one(f))
        assertEquals(5 to 100, w.streamId to w.increment)
        // and it is 0 when we write it
        assertEquals(0, FrameEncoder.windowUpdate(Int.MAX_VALUE, Int.MAX_VALUE)[5].toInt() and 0x80)
    }

    @Test
    fun errorCodesOfSection7() {
        assertEquals(14, Http2ErrorCode.entries.size)
        assertEquals(Http2ErrorCode.HTTP_1_1_REQUIRED, Http2ErrorCode.of(0xd))
        assertEquals(Http2ErrorCode.INTERNAL_ERROR, Http2ErrorCode.of(0xff)) // unknown: no special behaviour (section 7)
    }
}
