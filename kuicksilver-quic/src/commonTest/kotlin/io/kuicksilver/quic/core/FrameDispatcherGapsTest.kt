// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class FrameDispatcherGapsTest {
    /**
     * RFC 9000 section 21.9: frames that make us work and change nothing spend glitch tokens. A STREAMS_BLOCKED repeating the last
     * reported limit is one; the first report of a limit is not.
     */
    @Test fun negative_repeatedStreamsBlockedAtTheSameLimitSpendsATokenEach() {
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            p.runUntil(300.milliseconds) { false }
            val before = p.server!!.stats.glitchTokensSpent
            repeat(3) { p.client.testInjectFrames += ONE_RTT to byteArrayOf(0x16, 0x00) } // STREAMS_BLOCKED (bidi), limit 0
            p.runUntil(1.seconds) { p.client.testInjectFrames.isEmpty() }
            p.runUntil(300.milliseconds) { false }
            assertEquals(2L, p.server!!.stats.glitchTokensSpent - before, "the second and third repeat the limit 0")
            assertNull(p.closedReason(p.serverEvents))
        }
    }

    /**
     * RFC 9221 section 3: max_datagram_frame_size is "the maximum size of a DATAGRAM frame (including the frame type, length, and
     * payload)"; a frame above it is PROTOCOL_VIOLATION. With a Length field (type 0x31, a two-byte varint for 97 and 98 bytes) the
     * limit 100 takes 97 payload bytes, not 98.
     */
    @Test fun negative_datagramWithLengthFieldCountsTheFieldAgainstTheLimit() {
        for ((payload, ok) in listOf(97 to true, 98 to false)) {
            val p = CorePair(serverQuic = quicConfig { maxDatagramFrameSize = 100 })
            p.use { _ ->
                assertTrue(p.handshake())
                p.runUntil(100.milliseconds) { false }
                val s = p.server!!
                p.client.timers.keepAlivePending = true
                p.batch.clear()
                check(p.client.poll(p.batch, p.now) == 1)
                val ping = p.batch.buffer(0).toByteArray(p.batch.length(0))
                val header = 1 + 8 + (ping[0].toInt() and 0x03) + 1 // Null crypto: plaintext header, the tag carries the packet number
                val frame = byteArrayOf(0x31, 0x40, payload.toByte()) + ByteArray(payload) { 0x61 }
                val d = ping.copyOf(header) + frame + ping.copyOfRange(ping.size - 16, ping.size)
                val b = PacketBuffer.of(d)
                try {
                    s.handleDatagram(b, d.size, io.kuicksilver.quic.CoreFixtures.clientAddr, io.kuicksilver.quic.Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
                val reason = p.closedReason(generateSequence { s.nextEvent() }.toList())
                if (ok) {
                    assertNull(reason, "a ${payload + 3}-byte frame fits max_datagram_frame_size 100")
                } else {
                    assertEquals(0x0aL, assertIs<QuicException.ConnectionLost.TransportClosed>(reason).code)
                }
            }
        }
    }

    private companion object {
        /** The 1-RTT level of `ConnectionCore.testInjectFrames`. */
        const val ONE_RTT = 3
    }
}
