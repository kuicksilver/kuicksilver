// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ClosedWriteChannelException
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The endpoint runtime under a misbehaving socket or application. */
class RuntimeRobustnessTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A DatagramIo whose receive and send can be shaped per test; delegates to an in-memory socket otherwise. */
    private class ShapedIo(
        private val inner: MemoryDatagramIo,
    ) : DatagramIo {
        var onReceive: (suspend (PacketBatch) -> Int?)? = null // null result: delegate
        var failSendsLeft = 0
        override val localAddress: InetSocketAddress get() = inner.localAddress
        override val capabilities: StateFlow<IoCapabilities> get() = inner.capabilities

        override suspend fun receive(into: PacketBatch): Int = onReceive?.invoke(into) ?: inner.receive(into)

        override suspend fun send(batch: PacketBatch): Int {
            if (failSendsLeft >
                0
            ) {
                failSendsLeft--
                throw IOException("sendmsg: EPERM")
            }
            return inner.send(batch)
        }

        override fun trySend(batch: PacketBatch): Int = inner.trySend(batch)

        override fun close() = inner.close()
    }

    private fun serverConfig(io: DatagramIo) =
        QuicEndpointConfig
            .Builder()
            .apply {
                server =
                    QuicServerConfig.Builder(CoreFixtures.server()).build()
                ; crypto = NullCryptoProvider
                this.io = { io }
            }.build()

    private fun clientConfig(io: DatagramIo) =
        QuicEndpointConfig
            .Builder()
            .apply {
                crypto = NullCryptoProvider
                this.io = { io }
            }.build()

    private val a = InetSocketAddress("10.0.0.1", 1111)
    private val b = InetSocketAddress("10.0.0.2", 2222)

    @Test fun closeWaitsForTheReceiverBeforeFreeingItsBatch() =
        runBlocking {
            withTimeout(20.seconds) {
                // the receive coroutine may still be inside the socket call with the batch's buffers when close() runs; those buffers must not be freed under it
                val net = MemoryNetwork()
                val io = ShapedIo(net.open(b))
                var touchedFreed = false
                var returned = false
                io.onReceive =
                    { into ->
                        kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { delay(300) }
                        try {
                            into.buffer(0)[0]
                        } catch (
                            e: IllegalStateException,
                        ) {
                            touchedFreed =
                                true
                        }
                        returned = true
                        0
                    } // like a receive blocked inside the native socket call: cancellation cannot interrupt it
                val ep = QuicEndpoint.bind(b, serverConfig(io))
                delay(50)
                ep.close()
                withTimeout(5.seconds) { while (!returned) delay(10) }
                delay(100)
                assertFalse(touchedFreed, "the receive buffer was freed while the socket call was still running")
            }
        }

    @Test fun receiveFailureClosesTheEndpoint() =
        runBlocking {
            withTimeout(20.seconds) {
                // a socket error ends the endpoint: accept() and connect() report EndpointClosing instead of hanging
                val net = MemoryNetwork()
                val io = ShapedIo(net.open(b))
                io.onReceive = { throw IOException("recvmsg: EBADF") }
                val ep = QuicEndpoint.bind(b, serverConfig(io))
                assertFailsWith<QuicException.EndpointClosing> { withTimeout(5.seconds) { ep.accept() } }
                assertFailsWith<QuicException.EndpointClosing> { ep.connect(a, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                ep.close()
            }
        }

    @Test fun oneFailedSendDoesNotKillTheEndpoint() =
        runBlocking {
            withTimeout(30.seconds) {
                // a transient send error (EPERM from a filter, an unreachable route) costs the datagrams of that batch, not the connection or the endpoint
                val net = MemoryNetwork()
                val sio = ShapedIo(net.open(b))
                sio.failSendsLeft = 1
                val cio = net.open(a)
                val server = QuicEndpoint.bind(b, serverConfig(sio))
                val client = QuicEndpoint.bind(a, clientConfig(cio))
                try {
                    val accepted = async { server.accept() }
                    val c = client.connect(b, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(10) { 1 }, 0, 10)
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    assertEquals(10, ss.input.readExactly(10).size)
                    c.close(0, "done")
                    s.close(0, "done")
                } finally {
                    client.close()
                    server.close()
                }
            }
        }

    @Test fun trySendDatagramAfterCloseAnswersClosed() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    // a closed connection does not answer QueueFull (a caller retrying on it would spin): the terminal answer is Closed (K6 D1)
                    val (c, s) = p.connect()
                    c.close(0, "done")
                    withTimeout(5.seconds) { c.closed.await() }
                    assertEquals(DatagramSendResult.Closed, c.trySendDatagram(byteArrayOf(1, 2, 3)))
                    s.close(0, "done")
                }
            }
        }

    @Test fun writeAfterPeerStopSendingIsAStreamError() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    // I7 (K5 report): the peer's STOP_SENDING surfaces as StreamError.Stopped on the writer, never as an IllegalStateException from the core
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(100), 0, 100)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.cancel(null) // STOP_SENDING
                    withTimeout(5.seconds) { while (st.output.closedCause == null) delay(10) }
                    val e = assertFailsWith<ClosedWriteChannelException> { st.output.flushAndClose() }
                    assertIs<QuicException.StreamError.Stopped>(e.cause, "cause: ${e.cause}")
                    assertFailsWith<ClosedWriteChannelException> {
                        st.output.writeFully(ByteArray(10), 0, 10)
                        st.output.flush()
                    }
                    c.close(0, "done")
                    s.close(0, "done")
                }
            }
        }
}
