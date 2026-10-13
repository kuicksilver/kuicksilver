// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.cancel
import io.ktor.utils.io.close
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class StreamBridgeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun <T> causes(t: Throwable): Sequence<Throwable> = generateSequence(t) { it.cause }

    @Test fun slowReaderBackpressureNoGrowth() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(90.seconds) {
                    val (c, s) = p.connect()
                    val total = 32 shl 20
                    val data = ByteArray(total) { (it * 7).toByte() } // more than the send buffer (4 MiB) plus the peer's window can hold
                    val writer =
                        async {
                            val st = c.openBidi()
                            st.output.writeFully(data, 0, data.size)
                            st.output.flushAndClose()
                            st
                        }
                    val st = s.acceptStream()
                    delay(1000)
                    assertTrue(s.stats.bytesInFlight < 2L * 1024 * 1024, "peer paused by flow control: in flight ${c.stats.bytesInFlight}")
                    assertFalse(writer.isCompleted, "writer blocked while the reader sleeps")
                    assertContentEquals(data, st.input.readExactly(total))
                    writer.await()
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun cancelledReaderSendsStopSendingConnectionSurvives() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readExactly(1)
                    assertFailsWith<TimeoutCancellationException> { withTimeout(100.milliseconds) { ss.input.readByte() } }
                    ss.input.cancel() // the reader gives up the stream
                    val e =
                        assertFailsWith<Throwable> {
                            repeat(100) {
                                st.output.writeFully(ByteArray(1000), 0, 1000)
                                st.output.flush()
                                delay(20)
                            }
                        }
                    assertTrue(
                        causes<Throwable>(e).any {
                            it is QuicException.StreamError.Stopped && it.code == 0L &&
                                it.initiator == Initiator.Peer
                        },
                        "$e",
                    )
                    val again = c.openBidi()
                    again.output.writeFully(byteArrayOf(2), 0, 1)
                    again.output.flushAndClose()
                    assertContentEquals(byteArrayOf(2), s.acceptStream().input.readExactly(1))
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun outputCloseWithCauseSendsResetStream() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readExactly(1)
                    st.output.close(IllegalStateException("give up"))
                    val e = assertFailsWith<Throwable> { withTimeout(10.seconds) { ss.input.readExactly(1) } }
                    assertTrue(
                        causes<Throwable>(e).any {
                            it is QuicException.StreamError.Reset &&
                                it.code == 0L &&
                                it.initiator == Initiator.Peer
                        },
                        "$e",
                    )
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun resetSurfacesAsStreamErrorReset() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readExactly(1)
                    st.reset(7)
                    val e = assertFailsWith<Throwable> { withTimeout(10.seconds) { ss.input.readExactly(1) } }
                    val r = causes<Throwable>(e).filterIsInstance<QuicException.StreamError.Reset>().first()
                    assertEquals(st.id, r.streamId)
                    assertEquals(7L, r.code)
                    assertEquals(Initiator.Peer, r.initiator)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun finDeliversEof() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(9), 0, 1)
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    assertContentEquals(byteArrayOf(9), ss.input.readExactly(1))
                    assertTrue(ss.input.readAvailable(ByteArray(4), 0, 4) < 0, "EOF after FIN")
                    c.close()
                    s.close()
                }
            }
        }

    /**
     * Data still buffered in the channel (written without a flush: `output` is auto-flushing, so `writeFully` sends at once)
     * leaves with the FIN in one STREAM frame on `flushAndClose`: no FIN-only frame in a packet of its own after the data
     * (interop `zerortt` with quiche: its hq server handled one FIN-only read per pass and left the last nine 0-RTT requests
     * unanswered).
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class)
    @Test
    fun flushAndCloseSendsDataAndFinInOnePacket() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val sink = PacketsWithStreamFrames()
                    val (c, s) = p.connect(quicConfig { qlog = sink })
                    val st = c.openBidi()
                    val req = "GET /a-file-name\r\n".encodeToByteArray()
                    st.output.writeBuffer.write(req, 0, req.size)
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    assertContentEquals(req, ss.input.readExactly(req.size))
                    assertTrue(ss.input.readAvailable(ByteArray(4), 0, 4) < 0, "EOF after FIN")
                    assertEquals(1, sink.count, "data and FIN in one packet")
                    c.close()
                    s.close()
                }
            }
        }

    /**
     * Requests closed together on many streams share packets: each `flushAndClose` hands its data and FIN to the core and
     * lets the closes already queued on the loop do the same before the packet is built (interop `zerortt`: one 303-byte
     * packet per request filled the initial window before the last 0-RTT requests left, and the runner counts what then
     * went in 1-RTT).
     *
     * The closes are queued on the loop's dispatcher before any of them runs: that is the case the yield covers. Calls that
     * reach the loop from another thread one by one share packets only as far as they arrive before the first close's turn
     * comes back, which depends on thread scheduling (on a loaded macOS host 21 of 30 runs took 3 packets when the ten
     * closes were dispatched from the test's thread).
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class)
    @Test
    fun concurrentClosesShareAPacket() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val sink = PacketsWithStreamFrames()
                    val (c, s) = p.connect(quicConfig { qlog = sink })
                    val req = "GET /a-file-name-of-some-length\r\n".encodeToByteArray()
                    val streams = List(10) { c.openBidi().also { it.output.writeBuffer.write(req, 0, req.size) } }
                    val loop = (streams[0] as io.kuicksilver.quic.runtime.StreamRuntime).loop.dispatcher
                    withContext(loop) { streams.map { st -> async { st.output.flushAndClose() } }.forEach { it.await() } }
                    repeat(10) { assertContentEquals(req, s.acceptStream().input.readExactly(req.size)) }
                    assertEquals(1, sink.count, "10 requests in ${sink.count} packets")
                    c.close()
                    s.close()
                }
            }
        }

    /** Counts the client's sent packets that carry a STREAM frame. */
    private class PacketsWithStreamFrames : QlogSink {
        @Volatile var count = 0

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace? =
            if (role != TlsRole.Client) {
                null
            } else {
                object : QlogTrace {
                    override fun write(record: String) {
                        if (record.contains("packet_sent") && record.contains("\"frame_type\":\"stream\"")) count++
                    }

                    override fun close() {}
                }
            }
    }

    @Test fun cancelledFlushLosesNoBytes() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    // a flush cancelled while the core's send buffer is full keeps every byte it had not handed over
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    val chunk = 48 * 1024
                    var next = 0

                    fun chunkOf(i: Int) = ByteArray(chunk) { (i * 31 + it / 7).toByte() }
                    kotlinx.coroutines.withTimeoutOrNull(100.milliseconds) {
                        while (true) {
                            val i = next++
                            st.output.writeFully(chunkOf(i), 0, chunk)
                        }
                    } // the server is not reading: the writer blocks, then is cancelled mid-flush
                    val total = next + 20
                    val reader =
                        async {
                            val ss = s.acceptStream()
                            val got = ByteArray(total * chunk)
                            var off = 0
                            while (true) {
                                val n =
                                    ss.input.readAvailable(
                                        got,
                                        off,
                                        got.size - off,
                                    )
                                ; if (n <
                                    0
                                ) {
                                    break
                                }
                                off += n
                                if (off ==
                                    got.size
                                ) {
                                    assertTrue(ss.input.readAvailable(ByteArray(1), 0, 1) < 0, "more bytes than written")
                                    break
                                }
                            }
                            got.copyOf(off)
                        }
                    while (next < total) {
                        val i = next++
                        st.output.writeFully(chunkOf(i), 0, chunk)
                    }
                    st.output.flushAndClose()
                    val got = reader.await()
                    assertEquals(total * chunk, got.size, "received bytes")
                    for (i in 0 until total) assertContentEquals(chunkOf(i), got.copyOfRange(i * chunk, (i + 1) * chunk), "chunk $i")
                    c.close()
                    s.close()
                }
            }
        }
}

private fun assertFalse(
    v: Boolean,
    msg: String,
) = assertTrue(!v, msg)
