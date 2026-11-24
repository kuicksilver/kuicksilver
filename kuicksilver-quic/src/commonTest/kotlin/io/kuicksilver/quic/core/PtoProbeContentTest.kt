// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.DatagramSender
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TestFrame
import io.kuicksilver.quic.nullOneRttFrames
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * What a PTO probe carries (RFC 9002 section 6.2.4): the frames of unacknowledged packets that hold something to resend, so a
 * peer whose acknowledgements are all lost still receives the data. Interop run 20261015-005204, kuicksilver->ngtcp2:handshakeloss:
 * the server's two oldest unacknowledged 1-RTT packets held only NEW_CONNECTION_ID frames and a PING, every client ACK was lost,
 * and for 30 s every probe repeated those two as ACK + PING; HANDSHAKE_DONE and the response, both lost once, were never resent.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class PtoProbeContentTest {
    @Test fun probesResendDataBehindPingOnlyPackets() {
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            p.runUntil(300.milliseconds) { false }
            val server = p.server!!
            // from here on every acknowledgement of the client is lost, and so is all the server sends until the data is out
            p.filterToServer = { _, _ -> false }
            p.filterToClient = { _, _ -> false }
            repeat(2) {
                server.timers.keepAlivePending = true
                p.step()
                p.advance(5.milliseconds)
            }
            val id = server.openStream(bidi = false, StreamPriority.Default)
            val data = ByteArray(1024) { it.toByte() }
            assertEquals(data.size, server.writeStream(id, data, 0, data.size, true))
            p.step()
            p.advance(5.milliseconds)
            var streamFrames = 0
            p.filterToClient = { _, b ->
                streamFrames += nullOneRttFrames(b)?.count { it is TestFrame.Stream } ?: 0
                true
            }
            val buf = ByteArray(4096)
            var read = 0
            val done =
                p.runUntil(10.seconds) {
                    while (true) {
                        val n = p.client.readStream(id, buf, 0, buf.size)
                        if (n <= 0) break
                        read += n
                    }
                    read == data.size
                }
            assertTrue(done, "the client got $read of ${data.size} bytes; STREAM frames that reached it: $streamFrames")
        }
    }

    /**
     * RFC 9002 section 6.2.4: a probe exists to repair loss and elicit an acknowledgment. With datagrams queued without an urgency
     * (they go ahead of stream data, RFC 9221 leaves the order to the sender) a probe was filled by a DATAGRAM, which is never
     * retransmitted, and the stream data its requeued packet held did not fit. The probe now carries the requeued STREAM frame
     * first and the datagram after it in the room left.
     */
    @Test fun probeCarriesTheRetransmissionBeforeDatagrams() {
        val p = CorePair()
        p.use { _ ->
            assertTrue(p.handshake())
            p.runUntil(300.milliseconds) { false }
            val client = p.client
            p.filterToServer = { _, _ -> false } // the stream data, and every packet after it, is lost
            val id = client.openStream(bidi = false, StreamPriority.Default)
            val data = ByteArray(600) { it.toByte() }
            assertEquals(data.size, client.writeStream(id, data, 0, data.size, true))
            p.step()
            p.advance(1.milliseconds)
            // from now on every packet with room gets a full-size datagram
            client.datagramSender =
                @OptIn(ExperimentalKuicksilverApi::class)
                object : DatagramSender {
                    override fun onTransmit(packet: DatagramPacketWriter) {
                        val n = packet.remaining
                        if (n > 0) packet.write(ByteArray(n), 0, n)
                    }
                }
            var resent: List<TestFrame>? = null
            p.filterToServer = { _, b ->
                val frames = nullOneRttFrames(b)
                if (resent == null && frames != null && frames.any { it is TestFrame.Stream && it.id == id }) resent = frames
                false
            }
            p.runUntil(5.seconds) { resent != null }
            val frames = resent
            assertTrue(frames != null, "a probe resent the stream data")
            val stream = frames.indexOfFirst { it is TestFrame.Stream && it.id == id }
            val datagram = frames.indexOfFirst { it is TestFrame.Datagram }
            assertTrue(datagram < 0 || stream < datagram, "STREAM before DATAGRAM: $frames")
            assertEquals(data.size, (frames[stream] as TestFrame.Stream).data.size, "the whole range")
        }
    }
}
