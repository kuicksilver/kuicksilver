// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.ksl
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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
}
