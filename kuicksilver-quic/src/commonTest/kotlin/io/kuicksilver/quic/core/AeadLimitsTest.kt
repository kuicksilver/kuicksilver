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
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicLimits
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.CipherSuites
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** RFC 9001 section 6.6: AEAD confidentiality and integrity limits. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class AeadLimitsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun confirmed(p: CorePair): Boolean =
        p.handshake() &&
            p.runUntil(limit = 2.seconds) { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed }

    private fun feedClient(
        p: CorePair,
        bytes: ByteArray,
    ) {
        val b = PacketBuffer.of(bytes)
        try {
            p.client.handleDatagram(b, bytes.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
        } finally {
            b.close()
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

    private fun forged(b: ByteArray): ByteArray =
        b.copyOf().also {
            it[it.size - 1] = (it[it.size - 1].toInt() xor 0x55).toByte()
        } // a flipped tag byte: authentication fails

    private fun isShort(b: ByteArray) = b[0].toInt() and 0x80 == 0

    /** Streams [size] bytes client → server; true when the server read everything. */
    private fun send(
        p: CorePair,
        size: Int,
        limit: Int = 60_000,
    ): Boolean {
        val id = p.client.openStream(bidi = true, StreamPriority.Default)
        var written = 0
        var read = 0
        val buf = ByteArray(16384)
        return p.runUntil(limit = limit.milliseconds) {
            if (written < size) written += p.client.writeStream(id, buf, 0, minOf(buf.size, size - written), fin = false)
            while (true) {
                val n = p.server!!.readStream(id, buf, 0, buf.size)
                if (n > 0) read += n else break
            }
            read >= size
        }
    }

    @Test fun negative_integrityLimit() {
        for ((forgeries, closes) in listOf(10 to true, 9 to false)) {
            val p = CorePair(clientQuic = quicConfig { limits = QuicLimits(integrityLimitAesGcm = 10) }, crypto = ksl)
            var captured: ByteArray? = null
            p.filterToClient = { _, b ->
                if (captured == null && isShort(b)) captured = b.copyOf()
                true
            }
            try {
                assertTrue(confirmed(p))
                assertTrue(send(p, 32 shl 10))
                val c = captured!!
                repeat(forgeries) { feedClient(p, forged(c)) }
                p.step()
                assertEquals(forgeries.toLong(), p.client.stats.authenticationFailures)
                val r = p.closedReason(p.clientEvents)
                if (closes) {
                    assertIs<QuicException.ConnectionLost.TransportClosed>(r, "closed at the integrity limit")
                    assertEquals(0x0fL, r.code)
                    assertEquals(Initiator.Local, r.initiator)
                } else {
                    assertNull(r, "one below the limit: alive")
                }
            } finally {
                p.close()
            }
        }
    }

    /** RFC 9001 section 6.6: at the integrity limit the endpoint closes "and not process any more packets". */
    @Test fun negative_noPacketProcessedAfterIntegrityLimit() {
        val p = CorePair(clientQuic = quicConfig { limits = QuicLimits(integrityLimitAesGcm = 10) }, crypto = ksl)
        var captured: ByteArray? = null
        var toClient = 0
        p.filterToClient = { _, b ->
            if (captured == null && isShort(b)) captured = b.copyOf()
            toClient++
            true
        }
        try {
            assertTrue(confirmed(p))
            assertTrue(send(p, 32 shl 10))
            repeat(10) { feedClient(p, forged(captured!!)) }
            assertEquals(ConnectionState.Closing, p.client.state)
            p.filterToServer = { _, _ -> false } // the server never hears the close and keeps sending
            val received = p.client.stats.packetsReceived
            val failures = p.client.stats.authenticationFailures
            val sentBefore = toClient
            val id = p.server!!.openStream(bidi = false, StreamPriority.Default)
            p.server!!.writeStream(id, ByteArray(4000), 0, 4000, fin = true)
            p.runUntil(limit = 200.milliseconds) { false }
            assertTrue(toClient > sentBefore, "the server kept sending")
            assertEquals(received, p.client.stats.packetsReceived, "nothing processed after AEAD_LIMIT_REACHED")
            assertEquals(failures, p.client.stats.authenticationFailures, "nothing even decrypted")
        } finally {
            p.close()
        }
    }

    @Test fun integrityLimitChaChaUsesItsOwnValue() {
        val p =
            CorePair(
                clientTls = CoreFixtures.client { cipherSuites = CipherSuites(listOf(CipherSuites.CHACHA20_POLY1305)) },
                clientQuic =
                    quicConfig {
                        limits =
                            QuicLimits(integrityLimitAesGcm = 100, integrityLimitChaCha = 5)
                    },
                crypto = ksl,
            )
        var captured: ByteArray? = null
        p.filterToClient = { _, b ->
            if (captured == null && isShort(b)) captured = b.copyOf()
            true
        }
        try {
            assertTrue(confirmed(p))
            assertTrue(send(p, 16 shl 10))
            repeat(5) { feedClient(p, forged(captured!!)) }
            p.step()
            val r = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r)
            assertEquals(0x0fL, r.code)
        } finally {
            p.close()
        }
    }

    @Test fun initialAeadFailuresNotCounted() {
        val p = CorePair(serverQuic = quicConfig { limits = QuicLimits(integrityLimitAesGcm = 5) }, crypto = ksl)
        try {
            p.step()
            val initial = p.lastClientInitial!! // the server exists and still holds Initial keys
            repeat(20) { feedServer(p, forged(initial)) }
            assertEquals(0L, p.server!!.stats.authenticationFailures, "Initial keys are public: their failures say nothing about the AEAD")
            assertTrue(confirmed(p))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun confidentialityLimitTriggersAutomaticUpdate() {
        val p = CorePair(clientQuic = quicConfig { limits = QuicLimits(confidentialityLimitAesGcm = 800) }, crypto = ksl)
        try {
            assertTrue(confirmed(p))
            assertTrue(send(p, 2 shl 20), "transfer continues across the automatic update")
            assertTrue(p.client.stats.keyUpdates >= 1, "updated at 7/8 of the limit: ${p.client.stats}")
            assertNull(p.closedReason(p.clientEvents))
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }

    @Test fun confidentialityLimitWithoutPossibleUpdateCloses() {
        // no ACK ever comes back after our update, so a second update is forbidden (section 6.1): the connection closes with AEAD_LIMIT_REACHED before the 25th packet of the key
        val p =
            CorePair(
                clientQuic =
                    quicConfig {
                        limits = QuicLimits(confidentialityLimitAesGcm = 24)
                        maxIdleTimeout = 600.seconds
                    },
                serverQuic =
                    quicConfig {
                        maxIdleTimeout =
                            600.seconds
                    },
                crypto = ksl,
            )
        ; try {
            assertTrue(confirmed(p))
            assertTrue(p.client.initiateKeyUpdate(p.now))
            var sealed = 0
            p.filterToServer = { _, b ->
                if (isShort(b)) sealed++
                true
            }
            p.filterToClient = { _, _ -> false }
            send(p, 1 shl 20, limit = 300_000) // cwnd-limited data, then PTO probes with exponential backoff
            val r = p.closedReason(p.clientEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r, "closed before the limit is exceeded: $r")
            assertEquals(0x0fL, r.code)
            assertTrue(sealed <= 24 + 3, "at most the limit plus the CONNECTION_CLOSE copies (one per PTO) left under this key: $sealed")
        } finally {
            p.close()
        }
    }
}
