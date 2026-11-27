// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.SocketTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.timeout
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.server.request.receiveChannel
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The engine's close of its HTTP/3 connections over a path that drops what the client sends for a moment, as a server's
 * full receive buffer does (about 208 KiB by default on Linux and Android, filled by an upload): JVM and Android, a UDP
 * relay between the client and the server.
 */
class H3OrderlyCloseTest {
    /**
     * Forwards UDP between one client and [upstream]; while [blackout] is on, every datagram of the client is dropped
     * ([dropped] counts them). The server's answers always pass.
     */
    private class Relay(
        upstream: InetSocketAddress,
    ) {
        private val down: DatagramChannel = DatagramChannel.open().bind(InetSocketAddress("127.0.0.1", 0))
        private val up: DatagramChannel = DatagramChannel.open().bind(InetSocketAddress("127.0.0.1", 0))

        @Volatile private var client: SocketAddress? = null

        /** Until this `System.nanoTime()`, the client's datagrams are dropped. */
        @Volatile var blackoutUntil = 0L

        @Volatile var dropped = 0

        val port: Int get() = (down.localAddress as InetSocketAddress).port

        private val toServer =
            thread(isDaemon = true, name = "relay-up") {
                val b = ByteBuffer.allocate(2048)
                while (true) {
                    b.clear()
                    client = runCatching { down.receive(b) }.getOrNull() ?: break
                    if (System.nanoTime() - blackoutUntil < 0) {
                        dropped++
                        continue
                    }
                    b.flip()
                    if (runCatching { up.send(b, upstream) }.isFailure) break
                }
            }

        private val toClient =
            thread(isDaemon = true, name = "relay-down") {
                val b = ByteBuffer.allocate(2048)
                while (true) {
                    b.clear()
                    runCatching { up.receive(b) }.getOrNull() ?: break
                    b.flip()
                    val to = client ?: continue
                    if (runCatching { down.send(b, to) }.isFailure) break
                }
            }

        fun close() {
            down.close()
            up.close()
            toServer.join()
            toClient.join()
        }
    }

    /**
     * Found on the API 24 emulator by the vendored contract test `HttpTimeoutTest.testSocketTimeoutWriteFailOnWritePerRequestAttributes`:
     * an upload's socket timeout resets its stream (H3_REQUEST_CANCELLED, RFC 9114 section 4.1.1) and the client is closed
     * at once; the reset and the CONNECTION_CLOSE that followed were both lost to the server, whose request and connection
     * stayed open until its idle timeout (30 s; the leak sentinel saw quic.connection, h3.session, 7 quic.stream and
     * h3.serverRequest open after 10 s). The close went out once and the socket closed after it, so loss recovery never
     * repeated the reset. Now the engine's close first waits (bounded) for its connections' frames to be acknowledged: the
     * reset is repeated once the path carries again, the server ends the request, and the close follows.
     */
    @Test fun aResetLostWithTheCloseStillReachesTheServerBeforeTheEngineCloses() =
        h3Test {
            val handlerEnded = CompletableDeferred<Unit>()
            val (server, port) =
                testServer {
                    routing {
                        post("/stall") {
                            try {
                                // takes 1 MiB and then nothing more: the client's upload stops on flow control
                                val input = call.receiveChannel()
                                val buffer = ByteArray(64 * 1024)
                                var read = 0
                                while (read < 1024 * 1024) {
                                    val n = input.readAvailable(buffer)
                                    if (n < 0) break
                                    read += n
                                }
                                awaitCancellation() // until the client abandons the request, or the connection ends
                            } finally {
                                handlerEnded.complete(Unit)
                            }
                        }
                    }
                }
            val relay = Relay(InetSocketAddress("127.0.0.1", port))
            try {
                val client = testClient(Http3DiscoveryMode.H3Only) { install(HttpTimeout) }
                val pool = (client.engine as KuicksilverEngine).h3
                // the timeout fires: from here, before the stream is reset, the server hears nothing of the client
                pool.socketTimeoutForTest = { relay.blackoutUntil = Long.MAX_VALUE }
                // the mechanism, not the bound: a slow device's PTO backoff may put the first probe after the blackout
                // beyond 1 s (the reset's probes go at 1, 3, 7 PTOs after it)
                pool.orderlyCloseTimeoutForTest = 10.seconds
                try {
                    assertFailsWith<SocketTimeoutException> {
                        client.post("https://127.0.0.1:${relay.port}/stall") {
                            setBody("x".repeat(4 * 1024 * 1024))
                            timeout { socketTimeoutMillis = 500 }
                        }
                    }
                } finally {
                    client.close()
                    // the close's CONNECTION_CLOSE falls into the blackout too, unless the engine waits for the reset first
                    relay.blackoutUntil = System.nanoTime() + 300_000_000L
                }
                assertTrue(relay.dropped > 0, "the reset of the timed-out request was dropped")
                assertNotNull(
                    withTimeoutOrNull(15.seconds) { handlerEnded.await() },
                    "the server's request ended: the reset reached it (${relay.dropped} datagrams of the client dropped)",
                )
            } finally {
                server.stopSuspend(0, 500)
                relay.close()
            }
        }
}
