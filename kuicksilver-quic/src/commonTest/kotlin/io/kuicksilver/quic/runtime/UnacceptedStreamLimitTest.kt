// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readRemaining
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Review h-quic: a peer stream counts as closed for MAX_STREAMS only once the application consumed it (StreamManager.countClosed),
 * so a peer cannot open streams the application never accepts. The runtime used to read a peer's RESET_STREAM itself at once
 * (ConnectionRuntime.drainEvents, StreamReset), so a peer that opened a stream and sent RESET_STREAM (+ STOP_SENDING on a
 * bidirectional one) got the stream counted closed and new MAX_STREAMS credit without the application ever calling
 * acceptStream, while every such stream waited in the unbounded `accepted` channel (two 16 KiB buffers each): 500 streams against
 * a limit of 10. Now the reset of a stream still waiting for acceptStream is consumed when acceptStream hands it out, as quic-go
 * counts a reset stream completed only once the application read the error (`receive_stream.go`, `isNewlyCompleted`).
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class UnacceptedStreamLimitTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_resetBidiStreamsDoNotBypassTheLimitOfUnacceptedStreams() =
        againstUnacceptingServer { c ->
            c.openBidi().also {
                it.reset(0)
                it.stopSending(0)
            }
        }

    @Test fun negative_resetUniStreamsDoNotBypassTheLimitOfUnacceptedStreams() =
        againstUnacceptingServer { c ->
            c.openUni().also {
                it.reset(0)
            }
        }

    /** Control: without the resets the limit held before the fix too. */
    @Test fun finishedStreamsStayCountedUntilAccepted() =
        againstUnacceptingServer(reset = false) { c ->
            c.openBidi().also {
                it.output.flushAndClose()
            }
        }

    /**
     * The client fills the server's limit of 10 with streams the server application has not accepted; an 11th open waits. Each
     * acceptStream then hands a stream (and its reset) to the application; once five were consumed the server grants five more.
     */
    private fun againstUnacceptingServer(
        reset: Boolean = true,
        open: suspend (QuicConnection) -> QuicStream,
    ) = runBlocking {
        withTimeout(60.seconds) {
            val net = MemoryNetwork()
            val serverAddr = InetSocketAddress("10.0.0.2", 2222)
            val sio = net.open(serverAddr)
            val cio = net.open(InetSocketAddress("10.0.0.1", 1111))
            val server =
                QuicEndpoint.bind(
                    serverAddr,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig
                                    .Builder(CoreFixtures.server())
                                    .apply {
                                        quic =
                                            quicConfig {
                                                maxBidiStreams = 10
                                                maxUniStreams = 10
                                            }
                                    }.build()
                            crypto = NullCryptoProvider
                            io = { sio }
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    cio.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = NullCryptoProvider
                            io = { cio }
                        }.build(),
                )
            try {
                val accepted = async { server.accept() }
                val c = client.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build())
                val sc = accepted.await()
                repeat(10) { open(c) }
                // the 11th waits for credit the server must not give while its application accepted nothing (was: 500 in ~130 ms)
                val eleventh = async { open(c) }
                assertNull(
                    withTimeoutOrNull(1.seconds) { eleventh.await() },
                    "an 11th stream opened; the server application accepted none of 10",
                )
                // handing a stream out lets its credit go once the application consumed it (here: the reset it sees on reading, or
                // the whole stream); the server grants more once half of its limit closed
                repeat(5) {
                    val st = sc.acceptStream()
                    if (reset) {
                        assertFailsWith<QuicException.StreamError> { st.input.readRemaining() }
                    } else {
                        assertTrue(st.input.readRemaining().exhausted())
                        st.output.flushAndClose()
                    }
                }
                eleventh.await()
                c.close()
            } finally {
                client.close()
                server.close()
            }
        }
    }
}
