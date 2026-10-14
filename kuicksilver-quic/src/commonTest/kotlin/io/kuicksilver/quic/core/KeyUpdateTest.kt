// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.crypto.NullPacketProtector
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.PacketProtector
import io.kuicksilver.tls.QuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9001 section 6: key update with precomputed next keys and a previous-phase window. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class KeyUpdateTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun confirmed(p: CorePair): Boolean =
        p.handshake() &&
            p.runUntil(limit = 2.seconds) { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed }

    /** Echoes [size] bytes client → server → client over one stream; true when everything came back. */
    private fun echo(
        p: CorePair,
        size: Int,
        limit: Int = 60_000,
    ): Boolean {
        val data = ByteArray(size) { (it * 31).toByte() }
        val id = p.client.openStream(bidi = true, StreamPriority.Default)
        var written = 0
        var echoedLen = 0
        val buf = ByteArray(16384)
        var serverDone = false
        return p.runUntil(limit = limit.milliseconds) {
            if (written <
                data.size
            ) {
                written +=
                    p.client.writeStream(
                        id,
                        data,
                        written,
                        minOf(65536, data.size - written),
                        fin =
                            written + minOf(65536, data.size - written) == data.size,
                    )
            }
            val s = p.server!!
            while (true) {
                val n = s.readStream(id, buf, 0, buf.size)
                if (n >
                    0
                ) {
                    s.writeStream(id, buf, 0, n, false)
                } else {
                    if (n < 0 &&
                        !serverDone
                    ) {
                        serverDone = true
                        s.writeStream(id, buf, 0, 0, true)
                    }
                    break
                }
            }
            while (true) {
                val n = p.client.readStream(id, buf, 0, buf.size)
                if (n > 0) echoedLen += n else break
            }
            echoedLen == data.size
        }
    }

    private fun feedServer(
        p: CorePair,
        bytes: ByteArray,
    ) {
        val b = PacketBuffer.of(bytes)
        try {
            p.server!!.handleDatagram(b, bytes.size, CoreFixtures.clientAddr, Ecn.NotEct, p.now)
        } finally {
            b.close()
        }
    }

    private fun isShort(b: ByteArray) = b[0].toInt() and 0x80 == 0

    @Test fun localUpdateFollowedByPeer() {
        for (crypto in listOf<QuicCrypto>(NullCryptoProvider, ksl)) {
            val p = CorePair(crypto = crypto)
            try {
                assertTrue(confirmed(p))
                assertTrue(p.client.initiateKeyUpdate(p.now), "client may update once confirmed and acknowledged")
                assertTrue(echo(p, 1 shl 20), "echo after the update with $crypto")
                assertEquals(1L, p.client.stats.keyUpdates)
                assertEquals(1L, p.server!!.stats.keyUpdates, "the server followed into phase 1")
                assertEquals(true, p.client.keyPhaseForTest!!.phase)
                assertEquals(true, p.server!!.keyPhaseForTest!!.phase)
                assertNull(p.closedReason(p.clientEvents))
                assertNull(p.closedReason(p.serverEvents))
            } finally {
                p.close()
            }
        }
    }

    @Test fun peerInitiatedUpdateUpdatesOurWriteKeys() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(confirmed(p))
            assertTrue(p.server!!.initiateKeyUpdate(p.now))
            assertTrue(echo(p, 256 shl 10))
            assertEquals(true, p.client.keyPhaseForTest!!.phase, "the client's write keys moved to phase 1")
            assertEquals(1L, p.client.stats.keyUpdates)
        } finally {
            p.close()
        }
    }

    @Test fun kslUpdateAes128Aes256ChaCha() {
        for (suite in listOf(CipherSuites.AES_128_GCM, CipherSuites.AES_256_GCM, CipherSuites.CHACHA20_POLY1305)) {
            val p = CorePair(clientTls = CoreFixtures.client { cipherSuites = CipherSuites(listOf(suite)) }, crypto = ksl)
            try {
                assertTrue(confirmed(p), suite)
                assertTrue(p.client.initiateKeyUpdate(p.now))
                assertTrue(echo(p, 256 shl 10), suite)
                assertEquals(1L, p.server!!.stats.keyUpdates, suite)
                assertNull(p.closedReason(p.serverEvents), suite)
            } finally {
                p.close()
            }
        }
    }

    @Test fun cannotInitiateBeforeConfirmed() {
        val p = CorePair(crypto = ksl)
        try {
            assertFalse(p.client.initiateKeyUpdate(p.now))
            p.runUntil { p.client.hasHandshakeKeys }
            assertFalse(p.client.initiateKeyUpdate(p.now), "not before the handshake is confirmed")
        } finally {
            p.close()
        }
    }

    @Test fun cannotInitiateAgainBeforeAckOfCurrentPhase() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(confirmed(p))
            assertTrue(p.client.initiateKeyUpdate(p.now))
            assertFalse(p.client.initiateKeyUpdate(p.now), "no packet of the new phase acknowledged yet")
            assertTrue(echo(p, 64 shl 10))
            assertTrue(p.runUntil(limit = 5.seconds) { p.client.initiateKeyUpdate(p.now) }, "after an ACK of the current phase")
            assertEquals(2L, p.client.stats.keyUpdates)
        } finally {
            p.close()
        }
    }

    /**
     * RFC 9001 section 6.1: after our own update the old read key stays until a packet of the new phase authenticated, not
     * for 3 x PTO from the update: an idle connection's peer still sends in the old phase.
     */
    @Test fun ownUpdateKeepsOldReadKeyUntilNewPhaseArrives() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(confirmed(p))
            p.filterToServer = { _, _ -> false } // the server never sees a packet of the new phase
            assertTrue(p.client.initiateKeyUpdate(p.now))
            val pto = p.client.pto()
            p.runUntil(limit = pto * 10) { false }
            val failuresBefore = p.client.stats.authenticationFailures
            val id = p.server!!.openStream(bidi = false, StreamPriority.Default)
            p.server!!.writeStream(id, ByteArray(100), 0, 100, fin = true)
            val buf = ByteArray(200)
            assertTrue(p.runUntil(limit = 1.seconds) { p.client.readStream(id, buf, 0, buf.size) > 0 }, "old-phase data still decrypts")
            assertEquals(failuresBefore, p.client.stats.authenticationFailures)
        } finally {
            p.close()
        }
    }

    /** RFC 9001 section 6.5: the next update waits 3 x PTO after the acknowledgment that confirmed the previous one. */
    @Test fun nextUpdateWaitsThreePtoAfterConfirmingAck() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(confirmed(p))
            assertTrue(p.client.initiateKeyUpdate(p.now))
            val kp = p.client.keyPhaseForTest!!
            val id = p.client.openStream(bidi = false, StreamPriority.Default)
            p.client.writeStream(id, ByteArray(100), 0, 100, fin = true)
            assertTrue(p.runUntil(limit = 2.seconds) { kp.confirmedAt != TimeMark.NEVER }, "a packet of the new phase acknowledged")
            assertFalse(p.client.initiateKeyUpdate(p.now), "not right after the confirming ACK")
            assertTrue(p.runUntil(limit = 5.seconds) { p.now >= kp.confirmedAt + p.client.pto() * 3 })
            assertTrue(p.client.initiateKeyUpdate(p.now), "3 x PTO later")
        } finally {
            p.close()
        }
    }

    private class Counting(
        val delegate: PacketProtector = NullPacketProtector,
    ) : PacketProtector by delegate {
        var nextCalls = 0

        override fun next(): PacketProtector {
            nextCalls++
            return Counting(delegate)
        }
    }

    @Test fun nextKeysPrecomputedAtInstall() {
        val read = Counting()
        val write = Counting()
        val kp = KeyPhase(read, write) { _, _ -> }
        assertEquals(1, read.nextCalls, "next read keys derived when the current ones are installed (RFC 9001 section 9.5)")
        assertEquals(1, write.nextCalls)
        assertEquals(false, kp.phase)
        kp.onPacketSent(0)
        kp.onPacketAcked(0, io.kuicksilver.quic.TimeMark(0))
        assertTrue(kp.initiate(io.kuicksilver.quic.TimeMark(0), 100.milliseconds))
        assertEquals(true, kp.phase)
        assertEquals(1, read.nextCalls, "the generation-0 protector is not asked again; the new current one derives the next")
        kp.close()
    }

    @Test fun headerProtectionKeyUnchangedAcrossUpdates() {
        val read = Counting()
        val write = Counting()
        val kp = KeyPhase(read, write) { _, _ -> }
        kp.onPacketSent(0)
        kp.onPacketAcked(0, io.kuicksilver.quic.TimeMark(0))
        kp.initiate(io.kuicksilver.quic.TimeMark(0), 100.milliseconds)
        assertSame(read, kp.hpRead, "header protection stays with the generation-0 key (RFC 9001 section 5.4)")
        kp.close()
    }

    @Test fun forgedPhaseFlipDoesNotCommit() {
        val p = CorePair(crypto = ksl)
        var captured: ByteArray? = null
        p.filterToServer =
            { _, b ->
                if (captured == null && isShort(b)) captured = b.copyOf()
                true
            }
        try {
            assertTrue(confirmed(p))
            assertTrue(echo(p, 32 shl 10))
            val c = captured!!
            val forged = c.copyOf()
            forged[0] = (forged[0].toInt() xor 0x04).toByte()
            val before = p.server!!.stats.packetsReceived
            feedServer(p, forged)
            assertEquals(false, p.server!!.keyPhaseForTest!!.phase, "a packet that fails authentication with the next keys changes nothing")
            assertEquals(before, p.server!!.stats.packetsReceived)
            assertTrue(echo(p, 32 shl 10))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun reorderedPreviousPhaseAcrossTwoUpdates() {
        // focus 1: phase-0 packets arriving after the first update decrypt with the previous keys for 3 x PTO; later they are dropped; a second update still works
        val p = CorePair(crypto = ksl)
        val old = ArrayList<ByteArray>()
        p.filterToServer =
            { _, b ->
                if (isShort(b) && old.size < 4) old += b.copyOf()
                true
            }
        try {
            assertTrue(confirmed(p))
            assertTrue(echo(p, 32 shl 10))
            assertTrue(old.size >= 2, "captured phase-0 datagrams")
            assertTrue(p.client.initiateKeyUpdate(p.now))
            assertTrue(echo(p, 32 shl 10))
            assertEquals(1L, p.server!!.stats.keyUpdates)
            val dup = p.server!!.stats.duplicatesDropped
            feedServer(p, old[0])
            assertEquals(dup + 1, p.server!!.stats.duplicatesDropped, "decrypted with the previous keys (and seen as the duplicate it is)")
            p.advance(5.seconds)
            p.step() // > 3 x PTO: previous keys are gone
            feedServer(p, old[1])
            assertEquals(
                dup + 1,
                p.server!!.stats.duplicatesDropped,
                "no previous keys: the old packet cannot be decrypted and is dropped silently",
            )
            assertTrue(p.client.initiateKeyUpdate(p.now))
            assertTrue(echo(p, 32 shl 10))
            assertEquals(2L, p.server!!.stats.keyUpdates)
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun newPhaseWithLowerPacketNumberIsKeyUpdateError() {
        // Null crypto authenticates anything: an old phase-0 datagram fed after the previous keys are gone "decrypts" with the next keys below the current phase → 0x0e (RFC 9001 section 6.4)
        val p = CorePair()
        var early: ByteArray? = null
        p.filterToServer =
            { _, b ->
                if (early == null && isShort(b)) early = b.copyOf()
                true
            }
        try {
            assertTrue(confirmed(p))
            assertTrue(echo(p, 16 shl 10))
            assertTrue(p.client.initiateKeyUpdate(p.now))
            assertTrue(
                echo(
                    p,
                    16 shl 10,
                ),
            )
            assertEquals(1L, p.server!!.stats.keyUpdates)
            p.advance(5.seconds)
            p.step()
            feedServer(p, early!!)
            p.step()
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0eL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun consecutivePeerUpdateWithoutOurAckIsKeyUpdateError() {
        // Null crypto: a copy of the first phase-1 datagram with its Key Phase bit flipped back arrives before the server's own phase-1 packets were acknowledged → 0x0e (RFC 9001 section 6.2)
        val p = CorePair()
        var injected = false
        p.filterToServer =
            { _, b ->
                if (!injected && isShort(b) &&
                    b[0].toInt() and 0x04 != 0
                ) {
                    injected = true
                    val twice = b.copyOf()
                    twice[0] = (twice[0].toInt() xor 0x04).toByte()
                    feedServer(p, b)
                    feedServer(p, twice)
                    false
                } else {
                    true
                }
            }
        try {
            assertTrue(confirmed(p))
            assertTrue(p.client.initiateKeyUpdate(p.now))
            echo(p, 16 shl 10, limit = 3000)
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r, "server saw: $r")
            assertEquals(0x0eL, r.code)
        } finally {
            p.close()
        }
    }
}
