// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Dgram
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.ksl
import io.kuicksilver.tls.QuicCrypto
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A receiver that drops every other datagram (a receive buffer overflowing, K7 F2.9: two sockets during a migration)
 * on a long return path sees one hole per lost packet. A peer that only sent within flow control has broken no
 * rule (RFC 9000 section 4.1), so the reassembly range limit must not close the connection over it.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class LossBurstTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun alternatingLossOnALongPathKeepsTheConnection() {
        for (crypto in listOf<QuicCrypto>(NullCryptoProvider, ksl)) burst(crypto)
    }

    private fun burst(crypto: QuicCrypto) {
        val p = CorePair(crypto = crypto)
        try {
            assertTrue(p.handshake())
            assertTrue(
                p.runUntil(limit = 2.seconds) {
                    p.client.state == ConnectionState.Confirmed &&
                        p.server!!.state == ConnectionState.Confirmed
                },
            )
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            val size = 16 shl 20
            val data = ByteArray(size) { (it * 13).toByte() }
            var written = 0
            var read = 0
            val buf = ByteArray(65536)
            val got = ByteArray(size)
            var burst = -1 // client datagrams into the burst; -1 before it
            var lostInBurst = 0
            p.filterToServer = { _, bytes ->
                if (burst >= 0 && burst < 1200 && bytes[0].toInt() and 0x80 == 0) {
                    if (burst++ % 2 == 1) {
                        lostInBurst++
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            }
            // a long return path (100 rounds, 500 ms): the window grows large and holes pile up for a whole RTT before anything is resent
            var round = 0
            val delayed = ArrayDeque<Pair<Int, Dgram>>()
            p.filterToClient = { _, bytes ->
                delayed += round + 100 to Dgram(bytes, CoreFixtures.serverAddr)
                false
            }
            val done =
                p.runUntil(limit = 300.seconds) {
                    round++
                    while (delayed.isNotEmpty() && delayed.first().first <= round) p.toClient += delayed.removeFirst().second
                    if (written <
                        size
                    ) {
                        written +=
                            p.client.writeStream(
                                id,
                                data,
                                written,
                                minOf(65536, size - written),
                                written + minOf(65536, size - written) == size,
                            )
                    }
                    while (true) {
                        val n = p.server!!.readStream(id, buf, 0, buf.size)
                        if (n <= 0) break
                        buf.copyInto(got, read, 0, n)
                        read += n
                    }
                    if (burst < 0 && read >= 4 shl 20) burst = 0 // congestion window grown: start the burst
                    read == size || p.closedReason(p.serverEvents) != null
                }
            assertNull(p.closedReason(p.serverEvents), "$crypto: server ($lostInBurst datagrams lost in the burst)")
            assertTrue(lostInBurst > 2 * 256, "the burst left more holes than the per-stream range limit: $lostInBurst")
            assertTrue(done)
            assertEquals(size, read)
            assertTrue(got.contentEquals(data))
        } finally {
            p.close()
        }
    }
}
