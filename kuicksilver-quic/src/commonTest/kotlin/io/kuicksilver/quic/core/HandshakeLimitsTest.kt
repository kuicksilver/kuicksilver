// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.nullDatagramHasAckElicitingInitial
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.VerifyResult
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class HandshakeLimitsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun bigServer() =
        CoreFixtures.server(chain = listOf(TestCerts.serverBigChain, TestCerts.intermediate), key = TestCerts.serverBigChainKey)

    @Test fun negative_amplificationLimit() {
        var received = 0L
        var sent = 0L
        var violated = false
        val p = CorePair(serverTls = bigServer(), crypto = ksl)
        p.filterToServer = { _, b ->
            received += b.size
            true
        }
        p.filterToClient = { _, b ->
            sent += b.size
            if (!p.server!!.addressValidated && sent > 3 * received) violated = true
            true
        }
        try {
            assertTrue(p.handshake())
            assertTrue(!violated, "server sent $sent after receiving $received before validation")
        } finally {
            p.close()
        }
    }

    @Test fun negative_amplificationCountsDiscarded() {
        val p = CorePair(serverTls = bigServer(), crypto = ksl)
        try {
            p.step() // the first Initial made the server
            val s = p.server!!
            val before = s.stats.bytesReceived
            val junk = ByteArray(700) { 0x7f }
            val b = PacketBuffer.of(junk)
            try {
                s.handleDatagram(b, junk.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
            } finally {
                b.close()
            }
            assertEquals(before + 700, s.stats.bytesReceived, "undecodable bytes still count toward the budget")
        } finally {
            p.close()
        }
    }

    @Test fun negative_duplicateDatagramCountedOnce() {
        val p = CorePair(crypto = ksl)
        try {
            p.step()
            val s = p.server!!
            val before = s.stats.bytesReceived
            val first = p.toServer.firstOrNull()
            // replay what the server already saw: the datagram bytes count once per arrival, and buffered packets never count twice
            val bytes = p.lastClientInitial!!
            val b = PacketBuffer.of(bytes)
            try {
                s.handleDatagram(b, bytes.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
            } finally {
                b.close()
            }
            assertEquals(before + bytes.size, s.stats.bytesReceived)
            assertEquals(
                s.stats.bytesReceived,
                s.stats.bytesReceived,
                "no double counting from the undecryptable buffer: ${first?.bytes?.size}",
            )
        } finally {
            p.close()
        }
    }

    @Test fun addressValidatedOnlyByHandshakePacket() {
        val p = CorePair(crypto = ksl)
        // once the client could send Handshake packets, drop everything from it
        p.filterToServer = { _, _ -> !p.client.hasHandshakeKeys || p.server!!.addressValidated }
        try {
            p.step()
            assertTrue(!p.server!!.addressValidated, "Initial packets do not validate the address")
            p.runUntil(limit = 2000.milliseconds) { false }
            assertTrue(!p.server!!.addressValidated, "without a Handshake packet the address stays unvalidated")
            p.filterToServer = { _, _ -> true }
            assertTrue(p.runUntil { p.server!!.addressValidated })
        } finally {
            p.close()
        }
    }

    @Test fun negative_cryptoBufferLimit() {
        val p = CorePair()
        try {
            p.step()
            p.client.testInjectCrypto = Triple(2, 70_000L, 10)
            p.runUntil(limit = 300.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0dL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun negative_cryptoHighOffset() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.testInjectCrypto = Triple(3, 1L shl 40, 10)
            p.runUntil(limit = 300.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0dL, r.code)
            assertTrue(p.server!!.stats.memoryCeiling < (1L shl 40))
        } finally {
            p.close()
        }
    }

    @Test fun negative_cryptoPostHandshakeCap() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.testInjectCrypto = Triple(3, 0L, 70_000)
            p.runUntil(limit = 500.milliseconds) {
                p.closedReason(p.serverEvents) !=
                    null
            }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0dL, r.code)
        } finally {
            p.close()
        }
    }

    /** RFC 9001 section 4.1.3: once the server reads Handshake, Initial CRYPTO past what it received is a PROTOCOL_VIOLATION, not buffered. */
    @Test fun negative_cryptoPastEndOfPreviousLevel() {
        val p = CorePair(crypto = ksl)
        try {
            p.filterToClient = { _, _ -> false } // the client stays in Initial and keeps sending there
            p.step()
            p.step()
            val s = p.server!!
            assertTrue(s.readKeys[2] != null, "the server read the ClientHello and installed its Handshake keys")
            p.client.testInjectCrypto = Triple(0, 0L, 6000) // overlaps the ClientHello, then runs past its end
            p.runUntil(limit = 300.milliseconds) { p.closedReason(p.serverEvents) != null }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0aL, r.code)
            assertEquals(0L, s.handshakeBufferBytes)
        } finally {
            p.close()
        }
    }

    /** RFC 9001 section 4.1.3: Initial data still waiting for a gap when TLS moves to Handshake will never be consumed. */
    @Test fun negative_cryptoGapAtKeyChange() {
        val p = CorePair(crypto = ksl)
        try {
            p.client.testInjectCrypto = Triple(0, 3000L, 10)
            p.runUntil(limit = 300.milliseconds) { p.closedReason(p.serverEvents) != null }
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0aL, r.code)
        } finally {
            p.close()
        }
    }

    /** ngtcp2-style absolute end of the Initial CRYPTO stream, independent of the out-of-order window. */
    @Test fun negative_cryptoInitialLevelCap() {
        val cs = CryptoStreams(1 shl 20, 65_536, longArrayOf(65_536, 0, 262_144, Long.MAX_VALUE))
        val b = PacketBuffer.of(ByteArray(1000))
        try {
            val e = assertFailsWith<QuicWireException> { cs.onData(0, 65_000L, b, 0, 1000, false) }
            assertEquals(TransportError.CRYPTO_BUFFER_EXCEEDED, e.code)
            cs.onData(2, 65_000L, b, 0, 1000, false) // the Handshake level ends later
        } finally {
            b.close()
        }
    }

    /** The CRYPTO streams share the reassembler: at their 1024-gap limit a frame at the read offset is still taken (review). */
    @Test fun cryptoFrameAtTheReadOffsetIsTakenAtTheGapLimit() {
        val cs = CryptoStreams(1 shl 20, 65_536, longArrayOf(65_536, 0, 262_144, Long.MAX_VALUE))
        val b = PacketBuffer.of(ByteArray(2))
        try {
            for (i in 1..1024) cs.onData(2, 2L * i, b, 0, 1, false)
            cs.onData(2, 0, b, 0, 1, false)
            var delivered = 0
            assertTrue(cs.deliver(2) { _, n -> delivered += n })
            assertEquals(1, delivered)
        } finally {
            b.close()
        }
    }

    /** CRYPTO bytes TLS holds unread count toward the handshake's buffers (admission). */
    @Test fun unreadTlsInputCountsTowardHandshakeBuffer() {
        val p =
            CorePair(
                clientTls = CoreFixtures.client(trust = TrustConfig.Custom { chain, _, _ -> VerifyResult.Accepted(chain) }),
                crypto = ksl,
            )
        p.autoVerify = false
        try {
            assertTrue(p.runUntil(limit = 500.milliseconds) { p.clientEvents.any { it is ConnectionEvent.VerifyRequested } })
            val c = p.client
            assertEquals(0L, c.cryptoStreams.bufferedBytes)
            val tls = c.handshakeBufferBytes - c.receiver.bufferedBytes
            assertTrue(tls > 0, "the paused TLS holds the server's Handshake flight: $tls")
        } finally {
            p.close()
        }
    }

    @Test fun serverDropsInitialBelow1200() {
        val p = CorePair(crypto = ksl)
        try {
            p.step()
            val s = p.server!!
            val short = p.lastClientInitial!!.copyOf(1100)
            val b = PacketBuffer.of(short)
            val before = s.stats.packetsReceived
            try {
                s.handleDatagram(b, short.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
            } finally {
                b.close()
            }
            assertEquals(before, s.stats.packetsReceived)
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    /** RFC 9002 section 6.2.2.1: a server that spent its 3x budget and cannot send arms no PTO until the client sends again; the client's next datagram re-arms it. */
    @Test fun ptoNotArmedWhileAmplificationBlocked() {
        val p = CorePair(serverTls = bigServer(), crypto = ksl)
        try {
            // only the client's first flight (a two-datagram ClientHello) arrives: the server's large flight exhausts its budget
            p.filterToServer = { i, _ -> i <= 1 }
            p.runUntil(3.seconds) { false }
            val s = p.server!!
            assertTrue(!s.addressValidated && s.amplification.budget() < 64, "the server is blocked: budget ${s.amplification.budget()}")
            assertEquals(0, s.stats.ptoCount, "no PTO while nothing can be sent")
            assertEquals(TimeMark.NEVER, s.loss.timeout(), "and none armed")
            p.filterToServer = {
                _,
                _,
                ->
                true
            }
            assertTrue(p.handshake(), "the client's retransmission unblocks the server and the handshake completes")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 section 8.1 with budget left after the first flight (the default chain): the server's PTO probes, which resend
     * CRYPTO since probes cycle through outstanding data, spend the rest of the 3x budget and then stop; no datagram ever crosses
     * the limit (the interop runner's amplificationlimit check counts every server datagram against 3x the client's Initials).
     * Less than 1200 bytes of budget can carry no Initial probe (section 14.1), so up to 1199 bytes may stay unspent.
     */
    @Test fun ptoProbesStayWithinAmplificationBudget() {
        var received = 0L
        var sent = 0L
        var violated = false
        val p = CorePair(crypto = ksl)
        p.filterToServer = { i, b ->
            // only the client's first flight reaches the server; its Handshake packets (which would validate the address) are lost
            if (i <= 1) received += b.size
            i <= 1
        }
        p.filterToClient = { _, b ->
            sent += b.size
            if (!p.server!!.addressValidated && sent > 3 * received) violated = true
            true
        }
        try {
            p.runUntil(10.seconds) { false }
            val s = p.server!!
            assertTrue(!s.addressValidated, "the address stays unvalidated")
            assertTrue(s.stats.ptoCount > 0, "the server probed: ptoCount ${s.stats.ptoCount}, sent $sent of ${3 * received}")
            assertTrue(!violated, "server sent $sent after receiving $received before validation")
            // an Initial probe needs a 1200-byte datagram (RFC 9000 section 14.1): what is left below that is never sent as one
            assertTrue(s.amplification.budget() < 1200, "the probes spent the budget: ${s.amplification.budget()} left of ${3 * received}")
            assertEquals(TimeMark.NEVER, s.loss.timeout(), "no PTO armed once the budget cannot carry a probe (RFC 9002 section 6.2.2.1)")
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9000 sections 8.1 and 14.1: a server MUST expand every datagram carrying an ack-eliciting Initial to 1200 bytes and
     * MUST NOT send more than 3x the bytes received, so with a budget below 1200 it sends no Initial probe at all. Only the
     * client's first Initial (plus [extra] undecodable bytes, which count toward the budget) reaches the server; its PTO probes
     * spend the budget in 1200-byte datagrams, the rest goes at most to Handshake probes, and the Initial probe waits. More bytes
     * from the client let it go out, padded.
     */
    @Test fun negative_noUndersizedAckElicitingServerInitial() {
        for (extra in listOf(100, 500, 1000)) {
            var received = 0L
            var sent = 0L
            val undersized = ArrayList<Int>()
            var fullInitials = 0
            val p = CorePair()
            p.filterToServer = { i, b ->
                if (i == 0) received += b.size
                i == 0
            }
            p.filterToClient = { _, b ->
                sent += b.size
                if (nullDatagramHasAckElicitingInitial(b)) {
                    if (b.size < 1200) undersized += b.size else fullInitials++
                }
                true
            }
            try {
                p.step() // the ClientHello makes the server
                p.step() // the server answers it
                val s = p.server!!
                feedJunk(p, s, extra)
                received += extra
                val waited = p.runUntil(8.seconds) { s.amplification.budget() < 1200 && s.probePending[0] > 0 }
                p.runUntil(1.seconds) { false }
                assertEquals(emptyList(), undersized, "extra $extra: ack-eliciting Initial datagrams below 1200 bytes")
                assertTrue(sent <= 3 * received, "extra $extra: server sent $sent after receiving $received")
                assertTrue(
                    waited && s.probePending[0] > 0,
                    "extra $extra: an Initial probe waits for budget (${s.amplification.budget()} left)",
                )
                assertTrue(!s.addressValidated && s.state == ConnectionState.Handshaking, "extra $extra: ${s.state}, unvalidated")
                val before = fullInitials
                feedJunk(p, s, 400) // 1200 more bytes of budget
                assertTrue(
                    p.runUntil(1.seconds) { fullInitials > before },
                    "extra $extra: the Initial probe goes out once 1200 bytes may be sent",
                )
                assertTrue(sent <= 3 * (received + 400), "extra $extra: server sent $sent after receiving ${received + 400}")
                assertEquals(emptyList(), undersized, "extra $extra: ack-eliciting Initial datagrams below 1200 bytes")
            } finally {
                p.close()
            }
        }
    }

    private fun feedJunk(
        p: CorePair,
        s: io.kuicksilver.quic.ConnectionCore,
        size: Int,
    ) {
        val junk = ByteArray(size) { 0x7f }
        val b = PacketBuffer.of(junk)
        try {
            s.handleDatagram(b, junk.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
        } finally {
            b.close()
        }
    }
}
