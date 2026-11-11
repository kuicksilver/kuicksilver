// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.endpoint.ZeroRttReplayRegister
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.QuicSessionTicket
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** RFC 9002 section 6.2.4: a PTO in one space also probes the other spaces with ack-eliciting packets in flight. */
@OptIn(ExperimentalKuicksilverApi::class)
class PtoProbeSpacesTest {
    /**
     * RFC 9002 section 6.2.4: on a PTO "the sender SHOULD send ack-eliciting packets from other packet number spaces with in-flight
     * data ... particularly ... when the client has both Handshake and Application Data in flight because the peer might only
     * have receive keys for one of the two". A client whose Finished and first 1-RTT data are unacknowledged (the Application
     * space arms no PTO before confirmation) used to probe only the Handshake space; its 1-RTT data waited for the handshake.
     */
    @Test fun aHandshakePtoAlsoProbesApplicationDataInFlight() {
        val p = CorePair()
        val batch = PacketBatch(16)
        try {
            val c = p.client
            assertTrue(p.runUntil { c.writeKeys[3] != null })
            p.filterToClient = { _, _ -> false } // nothing of the server reaches the client any more
            val id = c.openStream(true)
            c.writeStream(id, ByteArray(3000), 0, 3000, false)
            p.step()
            assertTrue(c.loss.space(SpaceId.Application).ackElicitingInFlight > 0, "1-RTT data in flight")
            assertTrue(c.loss.space(SpaceId.Handshake).ackElicitingInFlight > 0, "the Finished in flight")
            assertTrue(!c.streams.hasStreamData(), "everything was sent once")
            val at = assertNotNull(c.nextTimeout())
            p.now = at
            c.onTimeout(at)
            assertEquals(1, c.probePending[SpaceId.Application.ordinal], "the Application space is probed with the Handshake space")
            assertTrue(c.streams.hasStreamData(), "its oldest data goes again")
            batch.clear()
            val n = c.poll(batch, at)
            var shortPackets = 0
            for (i in 0 until n) if (containsShortHeaderPacket(batch.buffer(i).toByteArray(batch.length(i)))) shortPackets++
            assertTrue(shortPackets > 0, "a 1-RTT packet went with the probe")
            assertEquals(0, c.probePending[SpaceId.Application.ordinal])
        } finally {
            batch.close()
            p.close()
        }
    }

    /** Whether the datagram holds a short-header packet behind its long-header ones. */
    private fun containsShortHeaderPacket(d: ByteArray): Boolean {
        var off = 0
        while (off < d.size) {
            val first = d[off].toInt() and 0xff
            if (first and 0x80 == 0) return true
            var q = off + 5
            q += 1 + (d[q].toInt() and 0xff)
            q += 1 + (d[q].toInt() and 0xff)
            if ((first shr 4) and 0x3 == 0) {
                val (tokenLength, k) = varint(d, q)
                q += k + tokenLength.toInt()
            }
            val (length, k) = varint(d, q)
            off = q + k + length.toInt()
        }
        return false
    }

    private fun varint(
        d: ByteArray,
        at: Int,
    ): Pair<Long, Int> {
        val size = 1 shl ((d[at].toInt() and 0xff) shr 6)
        var v = (d[at].toLong() and 0x3f)
        for (i in 1 until size) v = (v shl 8) or (d[at + i].toLong() and 0xff)
        return v to size
    }

    /** A full handshake that leaves the client a ticket for 0-RTT. */
    private fun ticket(): QuicSessionTicket {
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                serverEarly = ServerEarlyData.of(QuicConfig.Default, CoreFixtures.server().alpn, null, ZeroRttReplayRegister(Random(5))),
            )
        try {
            assertTrue(p.handshake())
            assertTrue(p.runUntil(limit = 2.seconds) { p.clientEvents.any { it is ConnectionEvent.SessionTicket } })
            val tickets = p.clientEvents.filterIsInstance<ConnectionEvent.SessionTicket>().map { it.ticket }
            tickets.dropLast(1).forEach { it.close() }
            return tickets.last()
        } finally {
            p.close()
        }
    }

    /**
     * A client's first flight with 0-RTT data that the server never answers: its Initial PTO also probes the 0-RTT data in flight
     * (the Application space arms no PTO before confirmation), in a 0-RTT packet.
     */
    @Test fun anInitialPtoAlsoProbesZeroRttDataInFlight() {
        KslLoader.ensureLoaded()
        val ticket = ticket()
        val p =
            CorePair(
                crypto = ksl,
                clientEarly = EarlyDataState.Allowed,
                clientSetup = { c ->
                    assertTrue(c.useTicket(ticket))
                    val id = c.openStream(bidi = true)
                    c.writeStream(id, ByteArray(500), 0, 500, fin = true)
                },
            )
        val batch = PacketBatch(16)
        try {
            p.filterToServer = { _, _ -> false }
            p.step()
            val c = p.client
            assertTrue(c.zeroRttWritable, "0-RTT keys")
            assertTrue(c.loss.space(SpaceId.Application).ackElicitingInFlight > 0, "0-RTT data in flight")
            val at = assertNotNull(c.nextTimeout())
            p.now = at
            c.onTimeout(at)
            assertEquals(1, c.probePending[SpaceId.Application.ordinal], "the 0-RTT data is probed with the Initial space")
            val n = c.poll(batch, at)
            var zeroRtt = 0
            for (i in 0 until n) zeroRtt += packetTypes(batch.buffer(i).toByteArray(batch.length(i))).count { it == 1 }
            assertTrue(zeroRtt > 0, "a 0-RTT packet went with the probe")
            assertEquals(0, c.probePending[SpaceId.Application.ordinal])
        } finally {
            batch.close()
            p.close()
            ticket.close()
        }
    }

    /** The long-header packet types (0 Initial, 1 0-RTT, 2 Handshake) of the datagram, in order. */
    private fun packetTypes(d: ByteArray): List<Int> {
        val out = ArrayList<Int>()
        var off = 0
        while (off < d.size && d[off].toInt() and 0x80 != 0) {
            val first = d[off].toInt() and 0xff
            out += (first shr 4) and 0x3
            var q = off + 5
            q += 1 + (d[q].toInt() and 0xff)
            q += 1 + (d[q].toInt() and 0xff)
            if ((first shr 4) and 0x3 == 0) {
                val (tokenLength, k) = varint(d, q)
                q += k + tokenLength.toInt()
            }
            val (length, k) = varint(d, q)
            off = q + k + length.toInt()
        }
        return out
    }
}
