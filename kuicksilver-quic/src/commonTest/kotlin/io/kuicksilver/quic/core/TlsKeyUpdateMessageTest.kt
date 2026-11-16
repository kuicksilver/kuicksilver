// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.QuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9001 section 6: "Endpoints MUST NOT send a TLS KeyUpdate message. Endpoints MUST treat the receipt of a TLS KeyUpdate
 * message as a connection error of type 0x010a, equivalent to a fatal TLS alert of unexpected_message".
 */
class TlsKeyUpdateMessageTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A CRYPTO frame (RFC 9000 section 19.6) carrying [message] at [offset] of the 1-RTT CRYPTO stream. */
    private fun cryptoFrame(
        offset: Long,
        message: ByteArray,
    ): ByteArray {
        require(offset < 64 && message.size < 64)
        return byteArrayOf(0x06, offset.toByte(), message.size.toByte()) + message
    }

    // HandshakeType key_update(24), a 24-bit length of 1, KeyUpdateRequest update_not_requested(0) (RFC 8446 section 4.6.3)
    private val keyUpdate = byteArrayOf(24, 0, 0, 1, 0)

    private fun confirmed(p: CorePair): Boolean =
        p.handshake() &&
            p.runUntil(limit = 2.seconds) { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed }

    private fun cryptos(): List<QuicCrypto> = listOf(ksl, NullCryptoProvider)

    @Test fun negative_tlsKeyUpdateFromClientIsCryptoError0x10a() {
        for (crypto in cryptos()) {
            val p = CorePair(crypto = crypto)
            p.use { _ ->
                assertTrue(confirmed(p), "$crypto")
                // a client sends nothing in the 1-RTT CRYPTO stream: the KeyUpdate starts it
                p.client.testInjectFrames.addLast(3 to cryptoFrame(0, keyUpdate))
                p.runUntil(limit = 2.seconds) { p.closedReason(p.serverEvents) != null }
                val r = p.closedReason(p.serverEvents)
                assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$crypto: $r")
                assertEquals(0x010aL, r.code, "$crypto")
            }
        }
    }

    @Test fun negative_tlsKeyUpdateFromServerIsCryptoError0x10a() {
        for (crypto in cryptos()) {
            val p = CorePair(crypto = crypto)
            p.use { _ ->
                assertTrue(confirmed(p), "$crypto")
                // after everything the server's TLS stack wrote at 1-RTT (its NewSessionTickets), so the client's TLS reads it next
                assertTrue(
                    p.runUntil(limit = 2.seconds) {
                        !p.server!!
                            .cryptoStreams.send[3]
                            .hasPending
                    },
                    "$crypto",
                )
                val end =
                    p.server!!
                        .cryptoStreams.send[3]
                        .written
                p.server!!.testInjectFrames.addLast(3 to cryptoFrame(end, keyUpdate))
                p.runUntil(limit = 2.seconds) { p.closedReason(p.clientEvents) != null }
                val r = p.closedReason(p.clientEvents)
                assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$crypto: $r")
                assertEquals(0x010aL, r.code, "$crypto")
            }
        }
    }

    /** Split over two CRYPTO frames, header first: the message is recognised wherever its bytes break. */
    @Test fun negative_tlsKeyUpdateSplitAcrossFramesIsCryptoError0x10a() {
        for (crypto in cryptos()) {
            val p = CorePair(crypto = crypto)
            p.use { _ ->
                assertTrue(confirmed(p), "$crypto")
                p.client.testInjectFrames.addLast(3 to cryptoFrame(0, keyUpdate.copyOfRange(0, 1)))
                p.client.testInjectFrames.addLast(3 to cryptoFrame(1, keyUpdate.copyOfRange(1, keyUpdate.size)))
                p.runUntil(limit = 2.seconds) { p.closedReason(p.serverEvents) != null }
                val r = p.closedReason(p.serverEvents)
                assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$crypto: $r")
                assertEquals(0x010aL, r.code, "$crypto")
            }
        }
    }

    /** A CRYPTO frame of any size (the offset and length as 4-byte varints, RFC 9000 section 16). */
    private fun bigCryptoFrame(
        offset: Long,
        message: ByteArray,
    ): ByteArray {
        fun v4(x: Long) = byteArrayOf((0x80 or (x shr 24).toInt()).toByte(), (x shr 16).toByte(), (x shr 8).toByte(), x.toByte())
        return byteArrayOf(0x06) + v4(offset) + v4(message.size.toLong()) + message
    }

    /** A message of another type whose body is full of key_update bytes: the framing skips bodies, so nothing is mistaken. */
    private fun otherMessage(bodyLength: Int) =
        byteArrayOf(99, (bodyLength shr 16).toByte(), (bodyLength shr 8).toByte(), bodyLength.toByte()) + ByteArray(bodyLength) { 24 }

    /** Null TLS keeps what it is given: only the transport's check can close the connection. */
    private fun sendToServer(vararg frames: ByteArray): CorePair {
        val p = CorePair(crypto = NullCryptoProvider)
        assertTrue(confirmed(p))
        for (f in frames) p.client.testInjectFrames.addLast(3 to f)
        p.runUntil(limit = 1.seconds) { p.closedReason(p.serverEvents) != null }
        return p
    }

    @Test fun negative_tlsKeyUpdateAfterOtherMessagesIsCryptoError0x10a() {
        val first = otherMessage(300) + otherMessage(0)
        val p =
            sendToServer(
                bigCryptoFrame(0, first.copyOfRange(0, 2)),
                bigCryptoFrame(2, first.copyOfRange(2, first.size) + keyUpdate),
            )
        try {
            val r = p.closedReason(p.serverEvents)
            assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$r")
            assertEquals(0x010aL, r.code)
        } finally {
            p.close()
        }
    }

    /** Control: the same messages without the KeyUpdate, split inside the length and inside the body, close nothing. */
    @Test fun keyUpdateBytesInsideOtherMessagesPass() {
        val m = otherMessage(300) + otherMessage(0) + otherMessage(70_000 - 4 - 304 - 4)
        val p =
            sendToServer(
                bigCryptoFrame(0, m.copyOfRange(0, 3)),
                bigCryptoFrame(3, m.copyOfRange(3, 200)),
                bigCryptoFrame(200, m.copyOfRange(200, 1000)),
            )
        try {
            assertNull(p.closedReason(p.serverEvents))
        } finally {
            p.close()
        }
    }
}
