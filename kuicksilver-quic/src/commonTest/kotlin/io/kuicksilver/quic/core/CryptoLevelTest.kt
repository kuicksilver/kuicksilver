// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.EncryptionLevel
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsRole
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9001 section 4.1.3: "When TLS provides keys for a higher encryption level, if there is data from a previous encryption level
 * that TLS has not consumed, this MUST be treated as a connection error of type PROTOCOL_VIOLATION."
 */
class CryptoLevelTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * Real TLS on both sides; the client's TLS reports Initial bytes it never read (as OpenSSL does for a message cut at the
     * end of the Initial flight). Once it reads the Handshake level, the client closes with PROTOCOL_VIOLATION.
     */
    @Test fun negative_initialBytesTlsLeftUnreadCloseTheConnectionOnceItReadsHandshake() {
        val p = CorePair(crypto = UnreadAtInitial(ksl))
        try {
            assertTrue(p.runUntil(5.seconds) { p.closedReason(p.clientEvents) != null })
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.clientEvents))
            assertEquals(0x0aL, r.code, "PROTOCOL_VIOLATION")
            assertTrue(r.message!!.contains("previous encryption level"), r.message)
        } finally {
            p.close()
        }
    }

    /** The control: the same pair without unread bytes completes the handshake. */
    @Test fun theSameHandshakeWithNothingUnreadCompletes() {
        val p = CorePair(crypto = ksl)
        try {
            assertTrue(p.handshake())
        } finally {
            p.close()
        }
    }

    /** [real]'s sessions; a client session also reports 3 unread bytes at the Initial level. */
    private class UnreadAtInitial(
        private val real: QuicCrypto,
    ) : QuicCrypto by real {
        override fun newSession(config: TlsConfig): QuicTlsSession = wrap(config, real.newSession(config))

        override fun newSession(
            config: TlsConfig,
            earlyData: Boolean,
        ): QuicTlsSession = wrap(config, real.newSession(config, earlyData))

        private fun wrap(
            config: TlsConfig,
            s: QuicTlsSession,
        ): QuicTlsSession =
            if (config.role != TlsRole.Client) {
                s
            } else {
                object : QuicTlsSession by s {
                    override fun pendingCryptoBytes(level: EncryptionLevel): Int =
                        s.pendingCryptoBytes(level) + if (level == EncryptionLevel.Initial) 3 else 0
                }
            }
    }
}
