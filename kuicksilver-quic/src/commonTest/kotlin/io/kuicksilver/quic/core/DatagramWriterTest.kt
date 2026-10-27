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
