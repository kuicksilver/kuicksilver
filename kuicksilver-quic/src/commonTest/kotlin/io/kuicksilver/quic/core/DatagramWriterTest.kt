// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.recovery.SentFrames
import io.kuicksilver.quic.wire.VarInt
import io.kuicksilver.quic.wire.WireWriter
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DatagramWriterTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * RFC 9221 section 5: a DATAGRAM frame is not fragmented, so it has to fit the packet. [DatagramWriter.remaining] is the
     * largest payload whose frame (type, Length varint, payload) fits the room left: with 66 bytes left it offered 64, whose
     * 2-byte Length makes a 67-byte frame, and the write overflowed the packet (an internal error closed the connection).
     * Every room from 1 to 20 000 bytes: the offered payload is written within the room, and one byte more would not fit.
     */
    @Test fun payloadOfRemainingAlwaysFits() {
        val buf = PacketBuffer.allocate(20_000)
        try {
            val writer = DatagramWriter()
            val frames = SentFrames()
            for (limit in 1..20_000) {
                val w = WireWriter(buf, 0, limit)
                writer.bind(w, frames, Int.MAX_VALUE)
                val r = writer.remaining
                if (r > 0) {
                    assertTrue(writer.write(ByteArray(r), 0, r, 0), "room $limit: payload $r")
                    assertTrue(w.pos <= limit, "room $limit: frame of ${w.pos} bytes")
                }
                val more = r + 1
                assertTrue(1 + VarInt.size(more.toLong()) + more > limit, "room $limit: $more bytes would fit too")
                writer.unbind()
            }
        } finally {
            buf.close()
        }
    }

    /**
     * An empty DATAGRAM (RFC 9221 section 4 allows one) is a 2-byte frame, type and a zero Length, but [DatagramWriter.remaining] is 0
     * both then and when no frame fits: a queue that wrote a full-size datagram and then an empty one into the 0 or 1 byte left
     * overflowed the packet (found by the connectionNull fuzz target). The write now refuses a frame that does not fit the room.
     */
    @Test fun emptyDatagramNeedsRoomForItsFrame() {
        val buf = PacketBuffer.allocate(16)
        try {
            val writer = DatagramWriter()
            val frames = SentFrames()
            for (limit in 0..2) {
                val w = WireWriter(buf, 0, limit)
                writer.bind(w, frames, Int.MAX_VALUE)
                assertEquals(0, writer.remaining, "room $limit")
                if (limit < 2) {
                    assertFalse(writer.write(ByteArray(0), 0, 0, 0), "room $limit: an empty frame does not fit")
                    assertEquals(0, w.pos, "room $limit: nothing written")
                } else {
                    assertTrue(writer.write(ByteArray(0), 0, 0, 7), "room $limit: an empty frame fits")
                    assertEquals(2, w.pos, "room $limit")
                    assertEquals(0x31, buf[0].toInt() and 0xff, "DATAGRAM with Length")
                    assertEquals(0, buf[1].toInt(), "a zero Length")
                    assertEquals(1, frames.dgCount)
                    assertEquals(7L, frames.dgId[0])
                }
                writer.unbind()
            }
        } finally {
            buf.close()
        }
    }

    /**
     * The queue's sequence: a datagram that fills the packet, then an empty one, which waits for the next packet instead of
     * overflowing this one (the fuzz input wrote it into the byte left).
     */
    @Test fun emptyDatagramAfterAFullOneWaitsForTheNextPacket() {
        val buf = PacketBuffer.allocate(100)
        try {
            val writer = DatagramWriter()
            for (limit in 4..100) {
                val w = WireWriter(buf, 0, limit)
                writer.bind(w, SentFrames(), Int.MAX_VALUE)
                val r = writer.remaining
                assertTrue(writer.write(ByteArray(r), 0, r, 0), "room $limit")
                val left = limit - w.pos
                assertEquals(left >= 2, writer.write(ByteArray(0), 0, 0, 1), "room $limit: $left bytes left")
                assertTrue(w.pos <= limit, "room $limit: frames of ${w.pos} bytes")
                writer.unbind()
            }
        } finally {
            buf.close()
        }
    }

    /** The peer's limit ([DatagramWriter.maxPayload]) still caps what is offered. */
    @Test fun remainingIsCappedByMaxPayload() {
        val buf = PacketBuffer.allocate(1500)
        try {
            val writer = DatagramWriter()
            writer.bind(WireWriter(buf, 0, 1500), SentFrames(), 100)
            assertEquals(100, writer.remaining)
            writer.unbind()
        } finally {
            buf.close()
        }
    }
}
