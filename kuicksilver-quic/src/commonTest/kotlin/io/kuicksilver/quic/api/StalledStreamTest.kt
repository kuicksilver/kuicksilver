// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.ConnectionRuntime
import io.kuicksilver.quic.sendCredit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Streams whose peer stops reading them, and never sends STOP_SENDING, must not stall the connection's other streams (RFC
 * 9000 section 4.1). Firefox 161 leaves a WebTransport stream so after `reader.cancel`; before, the stalled stream's writer
 * filled the connection's shared send buffer (`flowControl { maxSendBuffer }`) with bytes past the peer's credit, and no
 * other stream could send until it ended. Now a write takes no byte past the stream's or the connection's credit: the
 * stalled writers wait, and the buffer holds only what the peer may take.
 */
class StalledStreamTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The server grants 16 KiB per stream and never more on a stream it does not read; its connection window is wide. */
    private val serverQuic =
        quicConfig {
            maxBidiStreams = 1000
            flowControl {
                initialStreamWindow = 16_384
                maxStreamWindow = 16_384
                initialConnectionWindow = 64_000_000
                maxConnectionWindow = 64_000_000
            }
        }

    /** Server side: every stream is kept (none is read unless asked), so the peer's streams stay unread and open. */
    private class Server(
        scope: CoroutineScope,
        s: QuicConnection,
    ) {
        val streams = Channel<QuicStream>(Channel.UNLIMITED)
        val job: Job = scope.launch { while (true) streams.send(s.acceptStream()) }

        suspend fun take(id: Long): QuicStream {
            while (true) {
                val st = streams.receive()
                if (st.id == id) return st
            }
        }
    }

    /** Sends [size] bytes on a new bidirectional stream the server reads; the time it took. */
    private suspend fun CoroutineScope.transfer(
        c: QuicConnection,
        server: Server,
        size: Int,
    ): kotlin.time.Duration {
        val start = TimeSource.Monotonic.markNow()
        val data = ByteArray(size) { (it * 7).toByte() }
        val st = c.openBidi()
        val writer =
            launch {
                st.output.writeFully(data, 0, size)
                st.output.flushAndClose()
            }
        val got = server.take(st.id).input.readByteArray(size)
        assertContentEquals(data, got)
        writer.join()
        return start.elapsedNow()
    }

    private fun scenario(smallStalled: Int) =
        runBlocking {
            withTimeout(120.seconds) {
                ApiPair.open(serverQuic = serverQuic).use { p ->
                    val (c, s) = p.connect()
                    val server = Server(this, s)
                    val jobs = ArrayList<Job>()
                    // a control stream, as HTTP/3's: opened first, small messages all through
                    val control = c.openUni()
                    control.output.writeFully(ByteArray(1), 0, 1)
                    control.output.flush()
                    val controlIn = server.take(control.id).input
                    controlIn.readByteArray(1)
                    // the throughput of a fresh stream before anything stalls
                    val before = transfer(c, server, 1_000_000)
                    val stalled = ArrayList<QuicStream>()

                    suspend fun stall(size: Int) {
                        val st = c.openBidi()
                        stalled += st
                        jobs +=
                            launch {
                                st.output.writeFully(ByteArray(size), 0, size)
                                st.output.flush()
                            }
                    }
                    stall(8_000_000)
                    repeat(smallStalled) { stall(20_000) }
                    // every stalled writer took the whole credit the server gave its stream and waits for more
                    for (st in stalled) {
                        while (st.sendCredit() > 0L) yield()
                    }
                    val core = (c as ConnectionRuntime).core
                    val buffered = withContext(c.loopDispatcherForTest) { core.streams.sendBufferedBytes }
                    assertTrue(buffered <= (stalled.size + 2) * 16_384L, "buffered $buffered: only what the peer may take")
                    assertTrue(jobs.all { it.isActive }, "the stalled writers wait")
                    // the control stream still moves
                    repeat(100) {
                        control.output.writeFully(ByteArray(100) { b -> b.toByte() }, 0, 100)
                        control.output.flush()
                    }
                    assertEquals(10_000, withTimeout(10.seconds) { controlIn.readByteArray(10_000) }.size)
                    // and a new stream gets the throughput it had before the stalls (in memory: well under a second either way)
                    val after = transfer(c, server, 1_000_000)
                    assertTrue(after < before * 10 + 2.seconds, "1 MB took $after with the stalled streams, $before before")
                    jobs.forEach { it.cancel() }
                    server.job.cancel()
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun negative_oneStalledStreamDoesNotStallTheOthers() = scenario(0)

    @Test fun negative_manyStalledStreamsDoNotStallTheOthers() = scenario(400)

    /**
     * A send buffer of a few bytes still carries a whole transfer: a write takes what fits and the writer waits for the rest.
     * With one byte every packet waits for its acknowledgement (up to the peer's 25 ms `max_ack_delay`), so those transfers are short.
     */
    @Test fun aTinySendBufferStillCarriesAStream() =
        runBlocking {
            for ((buffer, size) in listOf(1L to 200, 1_024L to 50_000, 16_384L to 200_000)) {
                withTimeout(60.seconds) {
                    ApiPair.open().use { p ->
                        val (c, s) = p.connect(quicConfig { flowControl { maxSendBuffer = buffer } })
                        val server = Server(this, s)
                        transfer(c, server, size)
                        server.job.cancel()
                        c.close()
                        s.close()
                    }
                }
            }
        }
}
