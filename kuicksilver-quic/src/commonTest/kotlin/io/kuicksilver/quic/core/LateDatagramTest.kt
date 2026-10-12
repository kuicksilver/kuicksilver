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
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.ksl
import io.kuicksilver.quic.recovery.SpaceId
import io.kuicksilver.tls.QuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9000 section 17.1 and appendix A.3: a datagram that arrives more than half a packet-number window late is decoded
 * to the wrong packet number, which only packet protection catches (the AEAD nonce is the packet number, RFC 9001
 * section 5.3). The test protection must catch it as well, or the receiver acknowledges a packet number the peer never
 * sent and the peer closes with PROTOCOL_VIOLATION (K7 F2.9: two sockets during a migration reorder that much).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class LateDatagramTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun datagramLatePastTheDecodeWindowIsDropped() {
        for (crypto in listOf<QuicCrypto>(NullCryptoProvider, ksl)) {
            val p = CorePair(crypto = crypto)
            try {
                assertTrue(p.handshake(), "$crypto: handshake")
                assertTrue(
                    p.runUntil(limit = 2.seconds) {
                        p.client.state == ConnectionState.Confirmed &&
                            p.server!!.state == ConnectionState.Confirmed
                    },
                    "$crypto: confirmed",
                )
                val clientSpace = p.client.loss.space(SpaceId.Application)
                var held: ByteArray? = null
                var heldPn = -1L
                p.filterToClient = { _, bytes ->
                    // hold back the first short-header datagram once the transfer is under way
                    if (held == null && bytes[0].toInt() and 0x80 == 0 && clientSpace.ack.largestReceived > 0) {
                        held = bytes
                        heldPn =
                            p.server!!
                                .loss
                                .space(SpaceId.Application)
                                .largestSent
                        false
                    } else {
                        true
                    }
                }
                val id = p.client.openStream(bidi = true, StreamPriority.Default)
                val data = ByteArray(1 shl 20)
                var written = 0
                val buf = ByteArray(16384)
                var delivered = false
                var after = 0
                p.runUntil(limit = 30_000.milliseconds) {
                    if (written < data.size) written += p.client.writeStream(id, data, written, minOf(65536, data.size - written), false)
                    while (true) {
                        val n = p.server!!.readStream(id, buf, 0, buf.size)
                        if (n <= 0) break
                        p.server!!.writeStream(id, buf, 0, n, false)
                    }
                    while (p.client.readStream(id, buf, 0, buf.size) > 0) Unit
                    // 130 packet numbers later the held one decodes 256 too high (it was sent with a one-byte packet number)
                    if (!delivered && held != null && clientSpace.ack.largestReceived >= heldPn + 130) {
                        delivered = true
                        // the Null protection leaves the header readable: the packet number took one byte
                        if (crypto === NullCryptoProvider) assertEquals(0, held!![0].toInt() and 0x03, "one-byte packet number")
                        assertTrue(
                            p.server!!
                                .loss
                                .space(SpaceId.Application)
                                .largestSent < heldPn + 256,
                            "$crypto: the misread number was never sent",
                        )
                        val b = PacketBuffer.of(held!!)
                        try {
                            p.client.handleDatagram(b, held!!.size, CoreFixtures.serverAddr, Ecn.NotEct, p.now)
                        } finally {
                            b.close()
                        }
                        assertTrue(
                            clientSpace.ack.largestReceived < heldPn + 256,
                            "$crypto: the late packet was not taken for ${heldPn + 256}",
                        )
                    }
                    // a few round trips more: the client acknowledges what it took the late packet for
                    delivered && ++after > 50
                }
                assertNotNull(held, "$crypto: a datagram was held back")
                assertTrue(delivered, "$crypto: the held datagram was delivered late")
                assertNull(p.closedReason(p.serverEvents), "$crypto: server")
                assertNull(p.closedReason(p.clientEvents), "$crypto: client")
            } finally {
                p.close()
            }
        }
    }
}
