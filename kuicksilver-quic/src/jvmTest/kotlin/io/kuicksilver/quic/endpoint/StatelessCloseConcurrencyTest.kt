// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.VersionProfile
import io.kuicksilver.quic.wire.ConnectionId
import io.kuicksilver.tls.KslQuicCrypto
import java.util.Collections
import java.util.concurrent.CountDownLatch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue

/** A stateless Initial CONNECTION_CLOSE written by several endpoint loops at once must come out byte-identical to a lone one (no shared header-protection scratch). */
class StatelessCloseConcurrencyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun write(t: Int): ByteArray {
        val out = PacketBuffer.allocate(1500)
        try {
            val n =
                StatelessClose.writeInitialClose(
                    out,
                    VersionProfile.V1,
                    ConnectionId(ByteArray(8) { (t * 31 + it).toByte() }),
                    ConnectionId(
                        ByteArray(8) {
                            (
                                t *
                                    7 +
                                    it
                            ).toByte()
                        },
                    ),
                    TransportError.INVALID_TOKEN,
                    KslQuicCrypto,
                )
            return out.toByteArray(n)
        } finally {
            out.close()
        }
    }

    @Test fun concurrentWritersProduceTheSameBytes() {
        val expected = List(4) { write(it) }
        val mismatches = Collections.synchronizedList(ArrayList<String>())
        val start = CountDownLatch(1)
        val workers =
            List(4) { t ->
                Thread {
                    start.await()
                    try {
                        repeat(2_000) {
                            if (!write(t).contentEquals(expected[t])) {
                                mismatches +=
                                    "thread $t"
                            }
                        }
                    } catch (e: Throwable) {
                        mismatches += "thread $t: $e"
                    }
                }
            }
        workers.forEach { it.start() }
        start.countDown()
        workers.forEach { it.join() }
        assertTrue(mismatches.isEmpty(), "${mismatches.size} corrupted packets, first: ${mismatches.firstOrNull()}")
    }
}
