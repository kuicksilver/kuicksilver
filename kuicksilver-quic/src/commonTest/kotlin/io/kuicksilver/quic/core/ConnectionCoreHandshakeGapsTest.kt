// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QuicLimits
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.quic.server
import io.kuicksilver.tls.CipherSuites
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ConnectionCoreHandshakeGapsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Runs [c]'s timers at their deadlines, without polling, until its first PTO has fired. */
    private fun untilFirstPto(
        p: CorePair,
        c: ConnectionCore,
    ) {
        repeat(50) {
            if (c.stats.ptoCount >= 1) return
            val t = c.nextTimeout() ?: error("no timer armed")
            if (t > p.now) p.now = t
            c.onTimeout(p.now)
        }
        error("no PTO")
    }

    /**
     * RFC 9002 section 6.2.4: "the sender SHOULD send ack-eliciting packets from other packet number spaces with in-flight data". A
     * server whose Initial PTO fires with its Handshake flight unacknowledged too probes the Handshake space with that flight's data.
     */
    @Test fun initialPtoAlsoResendsTheHandshakeFlight() {
        val p = CorePair()
        try {
            p.filterToServer = { i, _ -> i == 0 } // the client's first Initial only: nothing the server sends is ever acknowledged
            p.runUntil(20.milliseconds) { false }
            val s = p.server!!
            assertTrue(s.loss.space(SpaceId.Handshake).ackElicitingInFlight > 0, "the server's Handshake flight is out")
            untilFirstPto(p, s)
            assertEquals(1, s.probePending[SpaceId.Handshake.ordinal], "the Handshake space is probed too")
            assertTrue(s.cryptoStreams.send[2].hasPending, "with the Handshake flight's CRYPTO data, not a bare PING")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9002 section 6.2.4: only spaces "with in-flight data" are probed along. A client whose Handshake PTO fires (its Finished
     * unacknowledged) does not probe the discarded Initial space, and the Application space only with ack-eliciting packets in flight.
     */
    @Test fun negative_handshakePtoProbesNoSpaceWithoutDataInFlight() {
        val p = CorePair()
        try {
            assertTrue(p.runUntil { p.clientEvents.any { it is ConnectionEvent.HandshakeCompleted } })
            p.filterToServer = { _, _ -> false }
            p.filterToClient = { _, _ -> false }
            val c = p.client
            assertTrue(c.loss.space(SpaceId.Handshake).ackElicitingInFlight > 0, "the Finished is unacknowledged")
            untilFirstPto(p, c)
            assertEquals(0, c.probePending[SpaceId.Initial.ordinal], "the Initial space is discarded")
            val appInFlight = c.loss.space(SpaceId.Application).ackElicitingInFlight
            val expected = if (appInFlight > 0) 1 else 0
            assertEquals(expected, c.probePending[SpaceId.Application.ordinal], "1-RTT ack-eliciting in flight: $appInFlight")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 14.1: "A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the
     * smallest allowed maximum datagram size of 1200 bytes", and only an Initial starts a server connection (section 7.2: the server's connection begins with the client's Initial). A
     * well-formed 1200-byte Handshake or 0-RTT long-header datagram for an unknown connection creates nothing.
     */
    @Test fun negative_aLongHeaderOtherThanInitialStartsNoServerConnection() {
        for (typeBits in listOf(1, 2)) { // 0-RTT, Handshake
            val d = ByteArray(1200)
            d[0] = (0xc0 or (typeBits shl 4)).toByte()
            d[4] = 1 // version 1
            d[5] = 8 // DCID length, DCID 6..13
            for (i in 6 until 14) d[i] = (i * 3).toByte()
            d[14] = 8 // SCID length, SCID 15..22
            for (i in 15 until 23) d[i] = (i * 5).toByte()
            val rest = 1200 - 25 // the Length field (2-byte varint) covers the packet number and payload to the datagram's end
            d[23] = (0x40 or (rest shr 8)).toByte()
            d[24] = (rest and 0xff).toByte()
            val b = PacketBuffer.of(d)
            try {
                val c =
                    ConnectionCore.server(
                        io.kuicksilver.quic.QuicConfig.Default,
                        CoreFixtures.server(),
                        io.kuicksilver.quic.NullCryptoProvider,
                        CoreFixtures.clientAddr,
                        kotlin.random.Random(5),
                        io.kuicksilver.quic.TimeMark(1_000_000_000L),
                        b,
                        d.size,
                    )
                if (c != null) c.release()
                assertTrue(c == null, "type bits $typeBits started a connection")
            } finally {
                b.close()
            }
        }
    }

    /**
     * RFC 9002 section 6.3: "Clients that receive a Retry packet reset congestion control and loss recovery state, including resetting
     * any pending timers"; the first flight the Retry answered is not lost (RFC 9000 section 17.2.5.2 sends it again) and costs nothing.
     */
    @Test fun negative_retryResetsLossStateWithoutDeclaringTheFirstFlightLost() {
        val p = EndpointPair { admission = ConnectionAdmission.AlwaysRetry }
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c))
            p.runUntil(500.milliseconds) { false }
            assertEquals(0L, c.stats.lostPackets, "the Initial packets the Retry answered are not losses")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9001 section 6.6: the confidentiality limit of AEAD_AES_128_GCM does not apply to AEAD_CHACHA20_POLY1305 ("the
     * confidentiality limit is greater than the number of possible packets (2^62) and so can be disregarded"). A ChaCha connection
     * with a 24-packet AES-GCM limit keeps sending well past 24 packets under one key.
     */
    @Test fun negative_aesGcmConfidentialityLimitDoesNotStopAChaChaKey() {
        val p =
            CorePair(
                clientTls = CoreFixtures.client { cipherSuites = CipherSuites(listOf(CipherSuites.CHACHA20_POLY1305)) },
                clientQuic = quicConfig { limits = QuicLimits(confidentialityLimitAesGcm = 24) },
                crypto = ksl,
            )
        try {
            assertTrue(p.handshake())
            val id = p.client.openStream(true)
            val buf = ByteArray(16384)
            var written = 0
            var read = 0
            assertTrue(
                p.runUntil(10_000.milliseconds) {
                    if (written < 200_000) written += p.client.writeStream(id, buf, 0, minOf(buf.size, 200_000 - written), false)
                    while (true) {
                        val n = p.server!!.readStream(id, buf, 0, buf.size)
                        if (n > 0) read += n else break
                    }
                    read >= 200_000
                },
                "200 kB (well over 24 packets) delivered: read $read",
            )
            assertEquals(0L, p.client.stats.keyUpdates, "no key update was needed")
        } finally {
            p.close()
        }
    }

    /** The first [ConnectionCore.NEW_TOKENS_KEPT] NEW_TOKEN frames of a connection are kept and cost nothing; the next one is a glitch. */
    @Test fun newTokensUpToTheKeptCountAreAllKept() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val c = p.client
            val glitches = c.stats.glitchTokensSpent
            val token = PacketBuffer.of(ByteArray(32) { 9 })
            try {
                repeat(ConnectionCore.NEW_TOKENS_KEPT) { c.onNewToken(token, 0, 32) }
                assertEquals(glitches, c.stats.glitchTokensSpent, "${ConnectionCore.NEW_TOKENS_KEPT} tokens are no glitch")
                assertEquals(ConnectionCore.NEW_TOKENS_KEPT, c.takeReceivedTokens().size)
                c.onNewToken(token, 0, 32)
                assertEquals(glitches + 1, c.stats.glitchTokensSpent, "one more is")
            } finally {
                token.close()
            }
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 6.2: "A client MUST discard any Version Negotiation packet if it has received and successfully processed any
     * other packet, including an earlier Version Negotiation packet." A client mid-handshake that processed the server's Initial
     * ignores a Version Negotiation listing none of its versions instead of giving up.
     */
    @Test fun negative_versionNegotiationAfterAServerPacketIsIgnored() {
        val p = CorePair(crypto = ksl)
        try {
            var allowed = 0
            p.filterToClient = { _, _ -> allowed++ < 1 } // the server's first datagram only: the handshake cannot finish
            assertTrue(p.runUntil(200.milliseconds) { p.client.anyPeerPacket })
            assertEquals(io.kuicksilver.quic.ConnectionState.Handshaking, p.client.state)
            p.client.onVersionNegotiation(intArrayOf(0x1a2a3a4a))
            assertEquals(io.kuicksilver.quic.ConnectionState.Handshaking, p.client.state, "the Version Negotiation packet was discarded")
        } finally {
            p.close()
        }
    }
}
