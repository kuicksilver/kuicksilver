// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.TlsRole
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A qlog sink never costs a file per forged Initial, and a failing sink never touches a connection. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class QlogRobustnessTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class CountingSink(
        val failOpen: Boolean = false,
        val failWrite: Boolean = false,
    ) : QlogSink {
        var opened = 0
        var closed = 0
        var records = 0

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace? {
            if (failOpen) throw IOException("EMFILE")
            opened++
            return object : QlogTrace {
                override fun write(record: String) {
                    if (failWrite) throw IOException("ENOSPC")
                    records++
                }

                override fun close() {
                    closed++
                }
            }
        }
    }

    private fun PacketBuffer.toByteArray(n: Int): ByteArray = ByteArray(n).also { copyTo(it, 0, 0, n) }

    @Test fun undecryptableInitialsOpenNoTraceThatStaysOpen() {
        val sink = CountingSink()
        val p = EndpointPair(crypto = KslQuicCrypto, serverQuic = quicConfig { qlog = sink })
        val b = PacketBatch(4)
        try {
            repeat(100) { i ->
                val c = p.connect()
                b.clear()
                check(c.poll(b, p.now) >= 1)
                val bytes = b.buffer(0).toByteArray(b.length(0))
                // inside the AEAD-protected payload: the Initial does not decrypt
                bytes[bytes.size - 20] = (bytes[bytes.size - 20].toInt() xor 0x5a).toByte()
                p.feed(p.server, bytes, InetSocketAddress("10.2.${i / 256}.${i % 256}", 40000))
            }
            assertEquals(0, p.server.connectionCount, "no state for forged Initials")
            assertEquals(0L, p.server.stats.connectionsCreated, "a forged Initial creates no connection")
            assertEquals(100L, p.server.stats.datagramsDroppedUndecryptable)
            assertEquals(sink.opened, sink.closed, "every trace that was opened is closed (opened ${sink.opened})")
        } finally {
            b.close()
            p.close()
        }
    }

    @Test fun aSinkThatCannotOpenLeavesTheConnectionAlone() {
        val sink = CountingSink(failOpen = true)
        val p = EndpointPair(serverQuic = quicConfig { qlog = sink })
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "handshake completes without a trace")
            assertNull(p.closed(c))
        } finally {
            p.close()
        }
    }

    @Test fun aTraceThatCannotWriteLeavesTheConnectionAlone() {
        val sink = CountingSink(failWrite = true)
        val p = EndpointPair(serverQuic = quicConfig { qlog = sink })
        try {
            val c = p.connect()
            assertTrue(p.confirmed(c), "handshake completes")
            assertNull(p.closed(c))
            assertTrue(
                p.server.connections().all {
                    p.closed(it) ==
                        null
                },
                "the server connection was not failed by its trace",
            )
            assertEquals(sink.opened, sink.closed, "a failing trace is closed and tracing stops")
        } finally {
            p.close()
        }
    }
}
