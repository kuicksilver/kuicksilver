// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.DatagramSender
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.quic.wire.localTransportParameters
import io.kuicksilver.tls.TlsRole
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9221: DATAGRAM frames in the core — transport parameter, payload limit, transmit hook, no retransmission, bounded receive queue. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class DatagramCoreTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Sends the queued payloads once each, records callbacks. */
    private class Sender : DatagramSender {
        val queue = ArrayDeque<Pair<ByteArray, Long>>()
        val acked = ArrayList<Long>()
        val lost = ArrayList<Long>()
        var transmits = 0
        var writes = 0
        var onTransmitCheck: (() -> Unit)? = null

        override fun onTransmit(packet: DatagramPacketWriter) {
            transmits++
            onTransmitCheck?.invoke()
            while (true) {
                val (d, id) =
                    queue.firstOrNull()
                        ?: break
                ; if (packet.remaining < d.size) break
                if (!packet.write(d, 0, d.size, id)) break
                queue.removeFirst()
                writes++
            }
        }

        override fun onAcked(id: Long) {
            acked += id
        }

        override fun onLost(id: Long) {
            lost += id
        }
    }

    private fun readAll(c: ConnectionCore): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        val buf = ByteArray(2000)
        while (true) {
            val n = c.readDatagram(buf, 0)
            if (n <
                0
            ) {
                break
            }
            out += buf.copyOf(n)
        }
        return out
    }

    @Test fun maxDatagramFrameSizeAdvertised() {
        assertEquals(
            65_535L,
            QuicConfig.Default.localTransportParameters(TlsRole.Client, ConnectionId(ByteArray(8)), null).maxDatagramFrameSize,
        )
        assertEquals(
            0L,
            quicConfig {
                maxDatagramFrameSize = 0
            }.localTransportParameters(
                TlsRole.Client,
                ConnectionId(ByteArray(8)),
                null,
            ).maxDatagramFrameSize,
            "0 means the parameter is absent",
        )
        assertEquals(128, QuicConfig.Default.datagramReceiveQueue)
    }

    @Test fun payloadLimitFromMtuAndPeer() {
        // min(peer max_datagram_frame_size, MTU - short header (1 + 8 + 4) - tag 16) minus the frame header (type + length varint) minus 32 bytes kept for a short ACK next to it
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            assertEquals(1200 - 29 - 3 - 32, p.client.maxDatagramPayload)
            assertEquals(1136, p.server!!.maxDatagramPayload)
        } finally {
            p.close()
        }
        val q = CorePair(serverQuic = quicConfig { maxDatagramFrameSize = 500 })
        try {
            assertTrue(q.handshake())
            assertEquals(497 - 32, q.client.maxDatagramPayload)
        } finally {
            q.close()
        }
    }

    @Test fun peerWithoutSupportGivesZero() {
        val p = CorePair(serverQuic = quicConfig { maxDatagramFrameSize = 0 })
        try {
            assertTrue(p.handshake())
            assertEquals(0, p.client.maxDatagramPayload)
            assertTrue(p.server!!.maxDatagramPayload > 0)
        } finally {
            p.close()
        }
    }

    @Test fun onTransmitCalledAtPacketAssembly() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val s = Sender()
            s.queue += ByteArray(300) { 7 } to 1L
            p.client.datagramSender = s
            assertTrue(
                p.runUntil(2.seconds) {
                    p.serverEvents.any { it is ConnectionEvent.DatagramsReadable }
                },
                "the server reports a readable datagram",
            )
            val got = readAll(p.server!!)
            assertEquals(1, got.size)
            assertContentEquals(ByteArray(300) { 7 }, got[0])
            assertEquals(1, s.writes)
            assertTrue(s.transmits >= 1)
            assertEquals(-1, p.server!!.readDatagram(ByteArray(10), 0), "queue empty")
        } finally {
            p.close()
        }
    }

    @Test fun ackedCallback() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val s = Sender()
            s.queue += ByteArray(10) to 42L
            p.client.datagramSender = s
            assertTrue(p.runUntil(2.seconds) { s.acked.isNotEmpty() })
            assertEquals(listOf(42L), s.acked)
            assertTrue(s.lost.isEmpty())
        } finally {
            p.close()
        }
    }

    @Test fun datagramNeverRetransmitted() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val s = Sender()
            s.queue += ByteArray(10) { 9 } to 5L
            var dropped = false
            p.filterToServer = { _, _ ->
                if (!dropped && s.writes == 1) {
                    dropped = true
                    false
                } else {
                    true
                }
            } // the datagram's packet vanishes
            p.client.datagramSender = s
            assertTrue(p.runUntil(5.seconds) { s.lost.isNotEmpty() }, "the loss is reported")
            assertEquals(listOf(5L), s.lost)
            p.runUntil(1.seconds) { false }
            assertTrue(readAll(p.server!!).isEmpty(), "nothing was resent (RFC 9221 section 5)")
            assertEquals(1, s.writes)
        } finally {
            p.close()
        }
    }

    @Test fun datagramsRespectCongestionWindow() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val id = p.client.openStream(true)
            p.client.writeStream(id, ByteArray(200_000), 0, 200_000, false)
            val s = Sender()
            var violations = 0
            s.onTransmitCheck =
                { if (p.client.stats.bytesInFlight >= p.client.stats.cwnd) violations++ }
            repeat(50) { s.queue += ByteArray(100) to it.toLong() }
            p.client.datagramSender = s
            assertTrue(p.runUntil(5.seconds) { s.writes == 50 })
            assertEquals(0, violations, "onTransmit never runs while the window is full")
        } finally {
            p.close()
        }
    }

    @Test fun negative_datagramInHandshakeLevel() {
        val p = CorePair()
        try {
            p.client.testInjectDatagramInHandshake = true
            assertTrue(p.runUntil(2.seconds) { p.closedReason(p.serverEvents) != null })
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.serverEvents))
            assertEquals(0x0aL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun datagramAboveAdvertisedSizeIsProtocolViolation() {
        // RFC 9221 section 3: a DATAGRAM frame larger than our max_datagram_frame_size is PROTOCOL_VIOLATION
        val p = CorePair(serverQuic = quicConfig { maxDatagramFrameSize = 100 })
        try {
            assertTrue(p.handshake())
            p.client.testInjectDatagramBytes = 500
            assertTrue(p.runUntil(2.seconds) { p.closedReason(p.serverEvents) != null })
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.serverEvents))
            assertEquals(0x0aL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun receiveQueueDropsOldestAt128() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val s = Sender()
            repeat(200) { i ->
                s.queue +=
                    ByteArray(4) { (i shr (8 * it)).toByte() } to i.toLong()
            }
            p.client.datagramSender = s
            assertTrue(p.runUntil(10.seconds) { s.acked.size == 200 })
            p.runUntil(200.milliseconds) { false }
            val got = readAll(p.server!!)
            assertEquals(128, got.size, "the queue keeps the newest 128")
            assertEquals(72L, p.server!!.stats.datagramsDropped)
            assertEquals(72, got[0][0].toInt() and 0xff or ((got[0][1].toInt() and 0xff) shl 8), "the first kept datagram is number 72")
            assertEquals(
                199,
                got[127][0].toInt() and 0xff or ((got[127][1].toInt() and 0xff) shl 8),
            )
        } finally {
            p.close()
        }
    }

    /** A datagram of exactly `maxDatagramPayload` must still go out while ACKs are being sent, without an ACK-only storm. */
    @Test fun maxSizeDatagramDeliveredWhileAcking() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val sid = p.server!!.openStream(true)
            p.server!!.writeStream(sid, ByteArray(20_000), 0, 20_000, false)
            p.runUntil(300.milliseconds) { false } // the client now has ACKs to send with every packet
            val size = p.client.maxDatagramPayload
            val s = Sender()
            s.queue += ByteArray(size) { 3 } to 1L
            p.client.datagramSender = s
            val sentBefore = p.client.stats.packetsSent
            assertTrue(
                p.runUntil(3.seconds) {
                    readAll(p.server!!).any {
                        it.size == size
                    } || s.lost.isNotEmpty()
                },
                "the full-size datagram was delivered (writes ${s.writes}, transmits ${s.transmits})",
            )
            assertEquals(1, s.writes)
            assertTrue(
                p.client.stats.packetsSent - sentBefore < 200,
                "no ACK-only storm: ${p.client.stats.packetsSent - sentBefore} packets",
            )
        } finally {
            p.close()
        }
    }

    /** RFC 9221 section 3: max_datagram_frame_size covers the whole frame; a type 0x30 frame (no Length field) of exactly that size is accepted, one byte more is not. */
    @Test fun typeWithoutLengthAtExactMax() {
        for ((payload, ok) in listOf(99 to true, 100 to false)) {
            val p = CorePair(serverQuic = quicConfig { maxDatagramFrameSize = 100 })
            try {
                assertTrue(p.handshake())
                p.runUntil(100.milliseconds) { false }
                val s = p.server!!
                p.client.timers.keepAlivePending = true
                p.batch.clear()
                check(p.client.poll(p.batch, p.now) == 1)
                val ping = p.batch.buffer(0).toByteArray(p.batch.length(0))
                val header = 1 + 8 + (ping[0].toInt() and 0x03) + 1 // Null crypto: plaintext header, zero tag
                val d = ping.copyOf(header) + byteArrayOf(0x30) + ByteArray(payload) { 0x61 } + ByteArray(16)
                val b = PacketBuffer.of(d)
                try {
                    s.handleDatagram(b, d.size, io.kuicksilver.quic.CoreFixtures.clientAddr, io.kuicksilver.quic.Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
                if (ok) {
                    assertNull(
                        p.closedReason(generateSequence { s.nextEvent() }.toList()),
                        "a ${payload + 1}-byte frame fits max_datagram_frame_size 100",
                    )
                    assertEquals(payload, s.readDatagram(ByteArray(200), 0))
                } else {
                    assertEquals(
                        0x0aL,
                        assertIs<QuicException.ConnectionLost.TransportClosed>(
                            p.closedReason(
                                generateSequence {
                                    s.nextEvent()
                                }.toList(),
                            ),
                        ).code,
                    )
                }
            } finally {
                p.close()
            }
        }
    }
}
