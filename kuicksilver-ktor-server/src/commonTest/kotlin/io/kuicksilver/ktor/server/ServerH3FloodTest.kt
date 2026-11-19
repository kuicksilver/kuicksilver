// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.glitchClockForTest
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.awaitSendStopped
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.updateAndGet
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

/**
 * The HTTP/3 form of Rapid Reset (CVE-2023-44487) against the server engine over a real loopback socket (threat model
 * 3.17; RFC 9114 section 10.5): a client that opens requests and resets them (STOP_SENDING and RESET_STREAM) never has
 * more handlers running than the streams it may open (100), and a flood of resets ends the connection with
 * H3_EXCESSIVE_LOAD.
 */
class ServerH3FloodTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Handlers {
        val running = MutableStateFlow(0)
        val maxRunning = MutableStateFlow(0)
        val started = MutableStateFlow(0)

        /** Released by the test: an uncooperative handler waits for it whatever happens, cancellation included. */
        val gate = CompletableDeferred<Unit>()

        suspend fun hold(cooperative: Boolean = true) {
            val n = running.updateAndGet { it + 1 }
            maxRunning.update { maxOf(it, n) }
            started.update { it + 1 }
            try {
                if (cooperative) awaitCancellation() else withContext(NonCancellable) { gate.await() }
            } finally {
                running.update { it - 1 }
            }
        }
    }

    private suspend fun rawH3(port: Int): Pair<QuicEndpoint, QuicConnection> {
        val ep = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
        val c =
            ep.connect(
                InetSocketAddress("127.0.0.1", port),
                QuicClientConfig.Builder(ServerFixtures.clientTls(alpn = listOf("h3"))).build(),
            )
        val control = c.openUni()
        control.output.writeFully(byteArrayOf(0x00, 0x04, 0x00)) // control stream, empty SETTINGS
        control.output.flush()
        return ep to c
    }

    /** A request for [path], reset in both directions once [beforeReset] returned. */
    private suspend fun QuicConnection.rapidReset(
        path: String,
        beforeReset: suspend () -> Unit = {},
    ) {
        val st = openBidi()
        st.output.writeFully(
            rawHeadersFrame(
                rawFieldSection(listOf(":method" to "GET", ":scheme" to "https", ":authority" to "server.test", ":path" to path)),
            ),
        )
        st.output.flush()
        beforeReset()
        st.stopSending(H3_REQUEST_CANCELLED)
        st.reset(H3_REQUEST_CANCELLED)
    }

    /**
     * Each request is reset once its handler runs, the strongest form: the transport is done with the stream at once,
     * but the handler is not, and it ignores the cancellation the engine sends it. The client gets no further than the 100
     * streams it may open while those handlers run.
     */
    @Test fun negative_h3RapidResetDoesNotRunHandlersUnbounded() =
        h3ServerTest {
            val handlers = Handlers()
            val (server, port) = tlsServer { routing { get("/hold") { handlers.hold(cooperative = false) } } }
            val (ep, c) = rawH3(port)
            try {
                coroutineScope {
                    val client =
                        launch {
                            runCatching {
                                repeat(1_000) { i -> c.rapidReset("/hold") { handlers.started.first { it > i } } }
                            }
                        }
                    withTimeout(15.seconds) { handlers.running.first { it == 100 } }
                    // the 100 resets reached the server long before this ends; a returned credit would start more handlers
                    assertNull(withTimeoutOrNull(3.seconds) { handlers.started.first { it > 100 } }, "a handler past the limit")
                    assertEquals(100, handlers.maxRunning.value)
                    client.cancel()
                }
            } finally {
                handlers.gate.complete(Unit)
                c.close()
                ep.close()
                server.stop(100, 500)
            }
            withTimeout(10.seconds) { handlers.running.first { it == 0 } }
        }

    /**
     * A handler that cooperates is cancelled once its client abandons the request (both directions reset), and the stream
     * goes back at once: 300 requests reset after their handler started all run, never more than 100 at a time, and none
     * is left running.
     */
    @Test fun abandonedRequestsCancelTheirHandlersAndFreeTheirStreams() =
        h3ServerTest {
            val handlers = Handlers()
            val (server, port) = tlsServer { routing { get("/hold") { handlers.hold() } } }
            val (ep, c) = rawH3(port)
            try {
                withTimeout(30.seconds) { repeat(300) { i -> c.rapidReset("/hold") { handlers.started.first { it > i } } } }
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
                assertEquals(300, handlers.started.value)
                assertTrue(handlers.maxRunning.value <= 100, "handlers at once: ${handlers.maxRunning.value}")
            } finally {
                c.close()
                ep.close()
                server.stop(100, 500)
            }
        }

    /** STOP_SENDING alone (a client that sent its whole request and no longer wants the answer) cancels the handler too. */
    @Test fun stopSendingAloneCancelsTheHandler() =
        h3ServerTest {
            val handlers = Handlers()
            val (server, port) = tlsServer { routing { get("/hold") { handlers.hold() } } }
            val (ep, c) = rawH3(port)
            try {
                val st = c.openBidi()
                st.output.writeFully(
                    rawHeadersFrame(
                        rawFieldSection(
                            listOf(
                                ":method" to "GET",
                                ":scheme" to "https",
                                ":authority" to "server.test",
                                ":path" to "/hold",
                            ),
                        ),
                    ),
                )
                st.output.flushAndClose()
                withTimeout(10.seconds) { handlers.started.first { it == 1 } }
                st.stopSending(H3_REQUEST_CANCELLED)
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
            } finally {
                c.close()
                ep.close()
                server.stop(100, 500)
            }
        }

    /** A connection lost while a handler holds its request (the client is gone without a word) cancels the handler. */
    @Test fun connectionLossCancelsTheHandler() =
        h3ServerTest {
            val handlers = Handlers()
            val (server, port) = tlsServer { routing { get("/hold") { handlers.hold() } } }
            val (ep, c) = rawH3(port)
            try {
                val st = c.openBidi()
                st.output.writeFully(
                    rawHeadersFrame(
                        rawFieldSection(
                            listOf(
                                ":method" to "GET",
                                ":scheme" to "https",
                                ":authority" to "server.test",
                                ":path" to "/hold",
                            ),
                        ),
                    ),
                )
                st.output.flushAndClose()
                withTimeout(10.seconds) { handlers.started.first { it == 1 } }
                c.close(0x101, "gone") // H3_GENERAL_PROTOCOL_ERROR: an abrupt end, no GOAWAY
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
            } finally {
                ep.close()
                server.stop(100, 500)
            }
        }

    /**
     * A flood of requests reset at once: every reset spends a token of the request-reset budget, and the connection ends with
     * H3_EXCESSIVE_LOAD. The server's budget clock is frozen, so exactly its 1000 tokens are spent whatever the host's
     * speed: with the clock running, a host that lets fewer than 33 resets a second through (a hosted Windows runner) refills
     * the bucket as fast as the flood empties it, and the connection never ended.
     *
     * Each request is held by its handler until the reset reaches it, so every reset comes before a complete response, and
     * every one is counted. A request the server had already answered in full (`call.respondText`, as before) is stopped
     * with H3_NO_ERROR once its response is complete (RFC 9114 section 4.1), and a client reset that comes after that stop
     * costs nothing (`H3Session.countClientReset`): on a host where the client's reset lost the race to the response, the
     * flood spent too few tokens and the connection stayed open (the Windows runner, run 44453449060). The flood's end is
     * kept as well as its count, so a flood that stops for another reason fails with that reason, not with a timeout.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @Test
    fun negative_h3RapidResetFloodEndsWithExcessiveLoad() =
        h3ServerTest {
            val handlers = Handlers()
            val (server, port) = tlsServer { routing { get("/hold") { handlers.hold() } } }
            server.engine.h3ConnectionForTest = { it.glitchClockForTest = { 0L } } // no refill: exactly 1000 tokens
            val (ep, c) = rawH3(port)
            try {
                var sent = 0
                val flood = runCatching { repeat(5_000) { c.rapidReset("/hold").also { sent++ } } } // fails once the server closed
                val closed =
                    withTimeoutOrNull(15.seconds) { c.closed.await() }
                        ?: fail("the connection is open after $sent resets; the flood ended with ${flood.exceptionOrNull()}")
                assertEquals(H3_EXCESSIVE_LOAD, assertIs<QuicException.ConnectionLost.ApplicationClosed>(closed).code)
                // the 1000 tokens were all spent first: the 1001st reset ended the connection, no earlier one
                assertTrue(sent > 1_000, "the connection ended after $sent resets")
                // the connection's end cancels whatever handler was still running
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
                // the server still serves a new connection
                val (ep2, c2) = rawH3(port)
                try {
                    assertTrue(!c2.closed.isCompleted)
                } finally {
                    c2.close()
                    ep2.close()
                }
            } finally {
                c.close()
                ep.close()
                server.stop(100, 500)
            }
        }

    /**
     * Rapid Reset by STOP_SENDING alone, against the engine: complete requests (HEADERS and FIN) whose responses the client
     * stops at once. Each stop cancels a held handler and gives its stream back, as a reset does, so each spends a token of the
     * same budget (RFC 9114 section 10.5): the 1001st ends the connection with H3_EXCESSIVE_LOAD. Before, the client never
     * reset anything and the flood went on at full speed, without end.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @Test
    fun negative_h3StopSendingFloodEndsWithExcessiveLoad() =
        h3ServerTest {
            val handlers = Handlers()
            val (server, port) = tlsServer { routing { get("/hold") { handlers.hold() } } }
            server.engine.h3ConnectionForTest = { it.glitchClockForTest = { 0L } } // no refill: exactly 1000 tokens
            val (ep, c) = rawH3(port)
            try {
                var sent = 0
                val flood =
                    runCatching {
                        repeat(5_000) {
                            val st = c.openBidi()
                            st.output.writeFully(rawHeadersFrame(rawFieldSection(HOLD)))
                            st.output.flushAndClose()
                            st.stopSending(H3_REQUEST_CANCELLED)
                            sent++
                        }
                    }
                val closed =
                    withTimeoutOrNull(15.seconds) { c.closed.await() }
                        ?: fail("the connection is open after $sent stops; the flood ended with ${flood.exceptionOrNull()}")
                assertEquals(H3_EXCESSIVE_LOAD, assertIs<QuicException.ConnectionLost.ApplicationClosed>(closed).code)
                assertTrue(sent > 1_000, "the connection ended after $sent stops")
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
            } finally {
                c.close()
                ep.close()
                server.stop(100, 500)
            }
        }

    /**
     * STOP_SENDING first, then the reset once the engine stopped the request in turn (it cancelled the handler): such a reset
     * follows our own STOP_SENDING and is never the client's, so before, neither half of the pair cost anything. The stop
     * counts once now (and a reset that came first instead takes its place, never a second token), and the flood ends with
     * H3_EXCESSIVE_LOAD.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @Test
    fun negative_h3StopSendingThenResetFloodEndsWithExcessiveLoad() =
        h3ServerTest {
            val handlers = Handlers()
            val (server, port) = tlsServer { routing { get("/hold") { handlers.hold() } } }
            server.engine.h3ConnectionForTest = { it.glitchClockForTest = { 0L } }
            val (ep, c) = rawH3(port)
            try {
                var sent = 0
                val flood =
                    runCatching {
                        repeat(5_000) {
                            val st = c.openBidi()
                            st.output.writeFully(rawHeadersFrame(rawFieldSection(HOLD))) // no FIN
                            st.output.flush()
                            st.stopSending(H3_REQUEST_CANCELLED)
                            // the engine's own STOP_SENDING, which a handler cancelled before its answer sends with the reset of
                            // the request; when none comes the reset goes anyway, as the client's own
                            withTimeoutOrNull(2.seconds) { st.awaitSendStopped() }
                            st.reset(H3_REQUEST_CANCELLED)
                            sent++
                        }
                    }
                val closed =
                    withTimeoutOrNull(15.seconds) { c.closed.await() }
                        ?: fail(
                            "the connection is open after $sent stopped and reset requests; the flood ended with ${flood.exceptionOrNull()}",
                        )
                assertEquals(H3_EXCESSIVE_LOAD, assertIs<QuicException.ConnectionLost.ApplicationClosed>(closed).code)
                // 1000 requests went whole; the 1001st one's stop ended the connection while the client waited for our stop
                assertTrue(sent >= 1_000, "the connection ended after $sent stopped and reset requests")
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
            } finally {
                c.close()
                ep.close()
                server.stop(100, 500)
            }
        }

    private companion object {
        const val H3_REQUEST_CANCELLED = 0x10cL
        const val H3_EXCESSIVE_LOAD = 0x107L
        val HOLD = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "server.test", ":path" to "/hold")
    }
}
