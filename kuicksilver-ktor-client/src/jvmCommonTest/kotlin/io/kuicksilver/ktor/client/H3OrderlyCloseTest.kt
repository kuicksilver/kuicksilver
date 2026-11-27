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
import io.kuicksilver.ktor.client.h3.H3Pool
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

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
     * repeated the reset. Now the engine's close first waits (bounded) for its connections' frames to be acknowledged,
     * sending them again at once as a probe: the server ends the request, and the close follows.
     *
     * The path stays dark from the timeout until the engine's wait starts: what brings the reset across is that wait's
     * own probe, not a probe timeout, so the outcome does not hang on the PTO backoff. The wait must end settled (the
     * server acknowledged everything, not the connection's end) and the engine's cleanup within the wait's bound and the
     * close's repeat.
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
                val client = testClient(Http3Discovery.H3Only) { install(HttpTimeout) }
                val engine = client.engine as KuicksilverEngine
                val pool = engine.h3
                val outcomes = CompletableDeferred<Triple<H3Pool.SettleOutcome, String?, Duration>>()
                // the timeout fires: from here, before the stream is reset, the server hears nothing of the client ...
                pool.socketTimeoutForTest = { relay.blackoutUntil = Long.MAX_VALUE }
                // ... until the engine's close starts waiting for its acknowledgments
                pool.settleStartedForTest = { relay.blackoutUntil = 0L }
                pool.settledForTest = { _, outcome, unsettled, took -> outcomes.complete(Triple(outcome, unsettled, took)) }
                try {
                    assertFailsWith<SocketTimeoutException> {
                        client.post("https://127.0.0.1:${relay.port}/stall") {
                            setBody("x".repeat(4 * 1024 * 1024))
                            timeout { socketTimeoutMillis = 500 }
                        }
                    }
                } finally {
                    client.close()
                }
                val closed = TimeSource.Monotonic.markNow()
                val bound = pool.orderlyCloseTimeoutForTest + H3Pool.CLOSE_REPEAT_CAP
                assertNotNull(withTimeoutOrNull(bound + 1.seconds) { engine.cleanup.join() }, "the engine's cleanup ended")
                val cleanupTook = closed.elapsedNow()
                val (outcome, unsettled, took) = assertNotNull(withTimeoutOrNull(1.seconds) { outcomes.await() }, "the wait ran")
                assertTrue(relay.dropped > 0, "the reset of the timed-out request was dropped")
                assertEquals(H3Pool.SettleOutcome.Settled, outcome, "the wait ended settled after $took; still waiting for: $unsettled")
                assertTrue(cleanupTook < bound + 300.milliseconds, "the engine's cleanup took $cleanupTook, bound $bound")
                assertNotNull(
                    withTimeoutOrNull(2.seconds) { handlerEnded.await() },
                    "the server's request ended: the reset reached it (${relay.dropped} datagrams of the client dropped)",
                )
            } finally {
                server.stopSuspend(0, 500)
                relay.close()
            }
        }
}
