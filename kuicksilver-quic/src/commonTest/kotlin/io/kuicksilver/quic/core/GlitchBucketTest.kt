// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.quicConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9000 section 21.9: the per-connection glitch token bucket (1000 tokens, 33/s) that closes a connection busy doing nothing useful. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class GlitchBucketTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun bucketSpendAndRefill() {
        val t0 = TimeMark(1_000_000_000L)
        val b = GlitchBucket(capacity = 1000, refillPerSecond = 33)
        assertEquals(1000, b.tokens)
        repeat(1000) { assertTrue(b.spend(t0), "token ${it + 1} of 1000 is there") }
        assertEquals(0, b.tokens)
        assertFalse(b.spend(t0), "the 1001st spend finds the bucket empty")
        assertEquals(1001L, b.spent)
        assertTrue(b.spend(t0 + 1.seconds))
        assertEquals(32, b.tokens, "one second refills 33 tokens, one was just spent")
        val full = GlitchBucket(1000, 33)
        full.spend(t0)
        full.spend(t0 + 1000.seconds)
        assertEquals(999, full.tokens, "the refill never exceeds the capacity")
    }

    @Test fun negative_glitchBucketCloses() {
        // 1001 NEW_CONNECTION_ID frames repeating a known sequence number within one second: the server closes with PROTOCOL_VIOLATION (0x0a) "excessive peer activity"
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { false }
            p.client.testInjectRepeatNewCid = 1001
            assertTrue(p.runUntil(limit = 1.seconds) { p.closedReason(p.serverEvents) != null }, "the server closes within the second")
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.serverEvents))
            assertEquals(0x0aL, r.code)
            assertEquals(Initiator.Local, r.initiator)
            assertTrue(r.reason.startsWith("excessive peer activity"), r.reason)
            assertTrue(p.server!!.stats.glitchTokensSpent >= 1001L)
        } finally {
            p.close()
        }
    }

    @Test fun slowMisbehaviourWithinRefillSurvives() {
        // 1000 duplicate NEW_CONNECTION_ID frames spread over 31 s stay under the 33/s refill: the connection lives
        val p = CorePair(clientQuic = quicConfig { maxIdleTimeout = 60.seconds }, serverQuic = quicConfig { maxIdleTimeout = 60.seconds })
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { false }
            repeat(1000) {
                p.client.testInjectRepeatNewCid = 1
                p.step()
                p.advance(31.milliseconds)
                p.step()
            }
            assertNull(p.closedReason(p.serverEvents))
            assertTrue(p.server!!.state == ConnectionState.Confirmed)
            assertTrue(p.server!!.stats.glitchTokensSpent in 990L..1000L, "spent ${p.server!!.stats.glitchTokensSpent}")
        } finally {
            p.close()
        }
    }

    @Test fun disabledNeverCloses() {
        val p = CorePair(serverQuic = quicConfig { glitchProtection = false })
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { false }
            p.client.testInjectRepeatNewCid = 3000
            p.runUntil(limit = 2.seconds) { p.client.testInjectRepeatNewCid == 0 }
            assertNull(p.closedReason(p.serverEvents))
            assertEquals(0L, p.server!!.stats.glitchTokensSpent)
        } finally {
            p.close()
        }
    }

    @Test fun duplicateNewConnectionIdAndRetireSpend() {
        // a NEW_CONNECTION_ID repeating a known sequence and every RETIRE_CONNECTION_ID cost a token (the peer makes us work for nothing)
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 300.milliseconds) { false }
            assertEquals(0L, p.server!!.stats.glitchTokensSpent, "the client's own NEW_CONNECTION_IDs after the handshake are not glitches")
            p.client.testInjectRepeatNewCid = 2
            p.runUntil(limit = 1.seconds) { p.client.testInjectRepeatNewCid == 0 }
            p.runUntil(limit = 300.milliseconds) { false }
            assertEquals(2L, p.server!!.stats.glitchTokensSpent, "sequence 1 sent again twice: two duplicates")
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun noOpWindowUpdatesSpendNothing() {
        // a MAX_DATA that raises nothing is what a retransmission or a reordered update looks like (quic-go sends MAX_STREAMS per packet until acknowledged): never a glitch
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.testInjectMaxData = 2000
            p.runUntil(limit = 2.seconds) { p.client.testInjectMaxData == 0 }
            p.runUntil(limit = 300.milliseconds) { false }
            assertEquals(0L, p.server!!.stats.glitchTokensSpent)
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun honestHandshakeAndIdleSpendNothing() {
        val p = CorePair(clientQuic = quicConfig { keepAlive = 1.seconds })
        try {
            assertTrue(p.handshake())
            p.runUntil(limit = 5.seconds) { false }
            assertEquals(0L, p.server!!.stats.glitchTokensSpent, "keep-alive PINGs once per second are not glitches")
            assertEquals(0L, p.client.stats.glitchTokensSpent)
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 10.3 / 12.2: short-header packets that fail decryption are discarded silently — anyone who sees a connection ID could otherwise close the connection with a thousand forged datagrams. */
    @Test fun negative_forgedShortHeadersFromStrangerSpendNothing() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val s = p.server!!
            val cid = s.localCid.toByteArray()
            val stranger = InetSocketAddress("10.0.0.9", 9999)
            val r = kotlin.random.Random(4)
            repeat(1100) {
                val dg = ByteArray(100) { r.nextInt().toByte() }
                dg[0] = 0x40
                cid.copyInto(dg, 1)
                val b = PacketBuffer.of(dg)
                try {
                    s.handleDatagram(b, dg.size, stranger, Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
            }
            p.runUntil(limit = 300.milliseconds) { false }
            assertEquals(ConnectionState.Confirmed, s.state)
            assertNull(p.closedReason(p.serverEvents))
            assertEquals(0L, s.stats.glitchTokensSpent, "forged packets spend nothing")
        } finally {
            p.close()
        }
    }

    /** A PTO fires two probes (RFC 9002 section 6.2.4); with nothing to retransmit both are PING (+ ACK) and arrive together. An honest pair is free, a third PING-only packet within one RTT is a glitch (found by testing.GlitchHonestTransferTest once ACK ranges shrank). */
    @Test fun ptoPairOfPingOnlyPacketsIsNotAGlitch() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.runUntil(300.milliseconds) { false }
            val s = p.server!!

            fun ping(): ByteArray {
                p.client.timers.keepAlivePending = true
                p.batch.clear()
                val n = p.client.poll(p.batch, p.now)
                check(n == 1) { "one datagram, got $n" }
                return p.batch.buffer(0).toByteArray(p.batch.length(0))
            }

            fun deliver(d: ByteArray) {
                val b = PacketBuffer.of(d)
                try {
                    s.handleDatagram(b, d.size, io.kuicksilver.quic.CoreFixtures.clientAddr, Ecn.NotEct, p.now)
                } finally {
                    b.close()
                }
            }
            val pings = List(3) { ping() }
            deliver(pings[0])
            deliver(pings[1])
            assertEquals(0L, s.stats.glitchTokensSpent, "the PTO pair is free")
            deliver(pings[2])
            assertEquals(1L, s.stats.glitchTokensSpent, "a third PING-only packet within one RTT costs a token")
        } finally {
            p.close()
        }
    }
}
