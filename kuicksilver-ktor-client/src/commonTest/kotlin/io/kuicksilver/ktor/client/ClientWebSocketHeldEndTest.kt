// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.client.request.get
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * The transport end a client session holds for Pongs after its own Close (RFC 6455 section 5.5.2: a Ping is answered
 * "unless it already received a Close frame"), and how the engine's close (`client.close()`) bounds it: the session goes
 * on answering Pings while the end is held, and the hold, with the wait for the server's end of the transport after it,
 * gets one bound: over HTTP/1.1 the grace, over HTTP/2 and HTTP/3, while the server's Close is missing, what is left of
 * T1 and at least the grace (WebSocketLifetime.serverWithin). Found by review probes of the int38 and int39 merge.
 */
class ClientWebSocketHeldEndTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val start = TimeSource.Monotonic.markNow()

    private fun now() = start.elapsedNow().inWholeMilliseconds

    /** What a raw server read from the client, in order: "close", "pong", then "FIN" or "RST" with its time. */
    private class Seen {
        val all = MutableStateFlow(emptyList<Pair<String, Long>>())

        fun add(
            e: String,
            at: Long,
        ) = all.update { it + (e to at) }

        fun count(e: String) = all.value.count { it.first == e }

        fun at(e: String) = all.value.firstOrNull { it.first == e }?.second

        suspend fun await(e: String) = withTimeout(20.seconds) { all.first { l -> l.any { it.first == e } } }
    }

    private suspend fun readClient(
        input: ByteReadChannel,
        seen: Seen,
    ) {
        try {
            while (true) {
                val b0 = input.readByte().toInt() and 0xff
                val b1 = input.readByte().toInt() and 0xff
                val len =
                    when (val l = b1 and 0x7f) {
                        126 -> input.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                        127 -> input.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
                        else -> l.toLong()
                    }
                if (b1 and 0x80 != 0) input.readByteArray(4)
                input.readByteArray(len.toInt())
                when (b0 and 0x0f) {
                    0x8 -> seen.add("close", now())
                    0xA -> seen.add("pong", now())
                }
            }
        } catch (_: Throwable) {
            seen.add(if (input.closedCause == null) "FIN" else "RST", now())
        }
    }

    private suspend fun ping(out: ByteWriteChannel) {
        out.writeFully(byteArrayOf(0x89.toByte(), 1, 7))
        out.flush()
    }

    /**
     * An HTTP/1.1 session that closes first, against a raw server that never sends its Close ([pings]: it Pings every
     * 50 ms after the client's Close; otherwise it is silent). [whileOpen] runs while the client is open, then
     * `client.close()`; returns what the server saw, when the client was closed and how long the engine's cleanup took.
     */
    private fun h1(
        pings: Boolean,
        grace: Long,
        whileOpen: suspend (KuicksilverEngine, Seen) -> Unit = { _, _ -> },
        then: (Seen, closedAt: Long, cleanupTook: Long) -> Unit,
    ) = clientTest {
        val seen = Seen()
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        try {
            coroutineScope {
                val server =
                    launch {
                        val socket = listener.accept()
                        try {
                            val i = socket.openReadChannel()
                            val o = socket.openWriteChannel(autoFlush = true)
                            o.writeStringUtf8(switchingProtocols(i.readWebSocketKey()))
                            o.flush()
                            launch { readClient(i, seen) }
                            seen.await("close")
                            while (pings) {
                                if (runCatching { ping(o) }.isFailure) break
                                delay(50)
                            }
                            kotlinx.coroutines.awaitCancellation()
                        } finally {
                            socket.close()
                        }
                    }
                val c = testClient(block = { install(WebSockets) })
                val e = c.engine as KuicksilverEngine
                e.h1.webSocketCloseWaitMillis = 60_000
                e.webSockets.hurryGraceMillis = grace
                val port = (listener.localAddress as InetSocketAddress).port
                c.webSocketSession("ws://127.0.0.1:$port/ws").close(CloseReason(4000, "bye"))
                seen.await("close")
                whileOpen(e, seen)
                val closedAt = now()
                c.close()
                withTimeout(30.seconds) { e.cleanup.join() }
                val took = now() - closedAt
                withTimeout(30.seconds) { seen.all.first { l -> l.any { it.first == "FIN" || it.first == "RST" } } }
                then(seen, closedAt, took)
                server.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /**
     * A server that keeps Pinging after the client's Close and never answers it: the open client's session goes on
     * answering, with no end of the connection. Before, Ktor's default session tried to answer on its closed outgoing
     * channel and ended the session after about 200 ms (a FIN over HTTP/1.1, RST_STREAM CANCEL over HTTP/2).
     */
    @Test fun negative_aServerPingingAfterOurCloseDoesNotEndTheSession() =
        h1(pings = true, grace = 200, whileOpen = { e, seen ->
            delay(800)
            assertEquals(null, seen.at("FIN") ?: seen.at("RST"), "the connection is still open: ${seen.all.value}")
            assertTrue(seen.count("pong") >= 8, "Pongs kept coming: ${seen.all.value}")
            assertEquals(1, e.webSockets.size, "the session still waits for the server's Close")
        }) { seen, _, _ ->
            assertEquals(null, seen.at("RST"), "a clean end: ${seen.all.value}")
        }

    /**
     * The same server and `client.close()`: Pings are still answered while the end is held, within the grace, and the
     * connection then ends cleanly, the cleanup within one grace (1 s here).
     */
    @Test fun pongsAreAnsweredDuringAHurriedHoldThatEndsWithinTheGrace() =
        h1(pings = true, grace = 1_000, whileOpen = { _, _ -> delay(200) }) { seen, closedAt, took ->
            val fin = seen.at("FIN")
            assertTrue(fin != null, "a clean end: ${seen.all.value}")
            assertTrue(
                seen.all.value.any {
                    it.first == "pong" && it.second in closedAt + 300 until fin
                },
                "Pongs after the engine's close: ${seen.all.value}",
            )
            assertTrue(took in 800L until 1_700L, "the cleanup took $took ms, the grace is 1000 ms")
        }

    /**
     * A silent server: the held end and the wait for the server's close after it share one grace (1 s), not one each.
     * Before, the cleanup took two (2022 ms).
     */
    @Test fun negative_aSilentServerCostsOneGrace() =
        h1(pings = false, grace = 1_000) { seen, _, took ->
            assertTrue(seen.at("FIN") != null, "a clean end: ${seen.all.value}")
            assertTrue(took < 1_700L, "the cleanup took $took ms, the grace is 1000 ms")
        }

    /**
     * HTTP/2: the stream's window takes exactly the client's Close (11 bytes); the server then reads nothing more and
     * Pings twice. The Pongs queue behind the closed window, and `client.close()` (300 ms after the Close arrived) gives the
     * held end the rest of T1 (a 4 s close wait). Its in-order end, which waits for the Pongs to leave, does not wait past
     * that bound: the stream is then reset. Before, the end waited a whole close wait more (6917 ms, 2898 ms of T1 left).
     */
    @Test fun negative_aHeldEndBehindAZeroWindowEndsWithinT1() =
        clientTest {
            val arrived = CompletableDeferred<Unit>()
            tlsH2WithSilentUdp(
                settings = io.kuicksilver.http2.http2Settings { initialStreamWindow = 11 },
                enableConnectProtocol = true,
                onRequest = { _, r ->
                    if (r.method != "CONNECT") {
                        r.respond(200, listOf("content-type" to "text/plain"))
                        r.sendBody(ByteReadChannel("ok".encodeToByteArray()), end = true)
                        return@tlsH2WithSilentUdp
                    }
                    r.respond(200)
                    val out = ByteChannel()
                    launch { runCatching { r.sendBody(out, end = true) } }
                    delay(800)
                    arrived.complete(Unit)
                    ping(out)
                    delay(600)
                    ping(out)
                    kotlinx.coroutines.awaitCancellation()
                },
            ) { port, _ ->
                val c = testClient(block = { install(WebSockets) })
                val e = c.engine as KuicksilverEngine
                e.h1.webSocketCloseWaitMillis = 4_000
                c.get("https://127.0.0.1:$port/")
                val s = c.webSocketSession("wss://127.0.0.1:$port/ws")
                val ownClose = TimeSource.Monotonic.markNow()
                s.close(CloseReason(4000, "bye"))
                withTimeout(10.seconds) { arrived.await() }
                delay(300)
                val left = 4_000 - ownClose.elapsedNow().inWholeMilliseconds
                val closed = TimeSource.Monotonic.markNow()
                c.close()
                withTimeout(30.seconds) { e.cleanup.join() }
                val took = closed.elapsedNow()
                assertTrue(took < (left + 1_200).milliseconds, "the cleanup took $took, $left ms of T1 were left")
            }
        }
}
