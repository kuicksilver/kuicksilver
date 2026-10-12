// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.api.ApiPair
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** [AsyncQlogSink]: the endpoint loop only queues; a slow sink loses records, never throughput. */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class AsyncQlogSinkTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A sink whose every call blocks its thread until [gate] opens (a stalled disk, an NFS mount gone away). */
    private class StalledSink : QlogSink {
        val gate = CompletableDeferred<Unit>()
        val opened = AtomicInt(0)
        val records = AtomicInt(0)
        val closed = AtomicInt(0)

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace {
            runBlocking { gate.await() }
            opened.incrementAndFetch()
            return object : QlogTrace {
                override fun write(record: String) {
                    runBlocking { gate.await() }
                    records.incrementAndFetch()
                }

                override fun close() {
                    closed.incrementAndFetch()
                }
            }
        }
    }

    @Test fun aStalledSinkDoesNotStallTheLoop(): Unit =
        runBlocking {
            val stalled = StalledSink()
            val sink = AsyncQlogSink(stalled, queueCapacity = 16)
            ApiPair.open(serverQuic = quicConfig { qlog = sink }).use { p ->
                withTimeout(20.seconds) {
                    // the server traces into a sink that blocks forever: the handshake and 256 KiB still go through
                    val payload = ByteArray(256 * 1024) { it.toByte() }
                    val (client, server) = p.connect()
                    val served =
                        async {
                            val s = server.acceptStream()
                            val b = ByteArray(16 * 1024)
                            var total = 0
                            while (true) {
                                val n = s.input.readAvailable(b, 0, b.size)
                                if (n < 0) break
                                total += n
                            }
                            s.output.writeFully(total.toString().encodeToByteArray())
                            s.output.flushAndClose()
                        }
                    val s = client.openBidi()
                    s.output.writeFully(payload)
                    s.output.flushAndClose()
                    val b = ByteArray(32)
                    val n = s.input.readAvailable(b, 0, b.size)
                    assertEquals(payload.size.toString(), b.decodeToString(0, n))
                    served.await()
                }
                // nothing new is queued from here on: what reaches the sink is what the queue held
                p.client.closeAndJoin()
                p.server.closeAndJoin()
                assertTrue(sink.dropped > 0, "the bounded queue overflowed instead of blocking: ${sink.dropped}")
                assertEquals(0, stalled.records.load(), "nothing reached the stalled sink yet")
                stalled.gate.complete(Unit)
                withTimeout(10.seconds) { sink.flush() }
                assertEquals(1, stalled.opened.load(), "the server's one trace")
                assertTrue(stalled.records.load() in 1..16, "at most the queue's capacity was kept: ${stalled.records.load()}")
            }
            sink.close()
        }

    private class MemorySink : QlogSink {
        val traces = ArrayList<StringBuilder>() // the writer's thread; read after flush()
        val closed = AtomicInt(0)

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace {
            val sb = StringBuilder()
            traces += sb
            return object : QlogTrace {
                override fun write(record: String) {
                    sb.append(record)
                }

                override fun close() {
                    closed.incrementAndFetch()
                }
            }
        }
    }

    @Test fun sampleEveryTracesOneConnectionInN(): Unit =
        runBlocking {
            val mem = MemorySink()
            val sink = AsyncQlogSink(mem, sampleEvery = 3)
            val traces = List(7) { sink.open("0$it", TlsRole.Server) }
            assertEquals(listOf(0, 3, 6), traces.indices.filter { traces[it] != null })
            assertNotNull(traces[0]).write("a")
            assertNull(traces[1])
            sink.flush()
            assertEquals(3, mem.traces.size)
            assertEquals("a", mem.traces[0].toString())
            sink.close()
        }

    @Test fun recordsKeepTheirOrderAndCloseClosesLiveTraces(): Unit =
        runBlocking {
            val mem = MemorySink()
            val sink = AsyncQlogSink(mem)
            val a = assertNotNull(sink.open("aa", TlsRole.Client))
            val b = assertNotNull(sink.open("bb", TlsRole.Client))
            repeat(100) { a.write("$it,") }
            b.write("x")
            a.close()
            a.write("after close") // ignored
            sink.flush()
            assertEquals((0 until 100).joinToString("") { "$it," }, mem.traces[0].toString())
            assertEquals(1, mem.closed.load())
            sink.close() // b is still open: closed with the sink, its record kept
            withTimeout(10.seconds) { while (mem.closed.load() < 2) kotlinx.coroutines.delay(10) }
            assertEquals("x", mem.traces[1].toString())
        }
}
