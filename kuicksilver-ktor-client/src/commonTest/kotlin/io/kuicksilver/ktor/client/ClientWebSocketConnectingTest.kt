// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.discard
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** RFC 6455 section 4.1, step 2: at most one WebSocket connection in the CONNECTING state per remote host. */
class ClientWebSocketConnectingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * Two WebSockets to two names of one address: the second connection is opened only once the first handshake was
     * answered ("even if the remote host is known by another name, the client MUST wait"; "There MUST be no more than one
     * connection in a CONNECTING state"). Before, both connected and sent their handshakes at once.
     */
    @Test fun negative_secondHandshakeToTheSameAddressWaitsForTheFirst() =
        clientTest {
            val firstHead = CompletableDeferred<Unit>()
            val secondAccepted = CompletableDeferred<Unit>()
            var firstAnswered = false
            var secondWhileConnecting = false
            rawServer({ index, input, output ->
                while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                if (index == 0) {
                    firstHead.complete(Unit)
                    // the second connection, if the client opens it now, arrives meanwhile
                    withTimeoutOrNull(500.milliseconds) { secondAccepted.await() }
                    firstAnswered = true
                }
                answer(input, output)
            }, onAccept = {
                if (it == 1) {
                    secondWhileConnecting = !firstAnswered
                    secondAccepted.complete(Unit)
                }
            }) { port ->
                testClient(
                    engine = { resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) } },
                    block = { install(WebSockets) },
                ).use { c ->
                    coroutineScope {
                        val opened = CompletableDeferred<Unit>()
                        launch { c.webSocket("ws://a.test:$port/") { opened.await() } }
                        firstHead.await()
                        launch { c.webSocket("ws://b.test:$port/") { opened.complete(Unit) } }
                    }
                    assertEquals(0, (c.engine as KuicksilverEngine).h1.webSocketConnecting.size(), "an entry outlived its WebSocket")
                }
            }
            assertFalse(secondWhileConnecting, "a second connection was in CONNECTING while the first was")
        }

    /**
     * The unit is the IP address: "If multiple connections to the same IP address are attempted simultaneously, the client
     * MUST serialize them" (RFC 6455 section 4.1, step 2). A WebSocket to another port of the address waits too. Before,
     * the keys were `ip:port`, and both handshakes were in flight at once.
     */
    @Test fun negative_handshakeToAnotherPortOfTheAddressWaits() =
        clientTest {
            val firstHead = CompletableDeferred<Unit>()
            val secondHead = CompletableDeferred<Unit>()
            var firstAnswered = false
            var secondWhileConnecting = false
            rawServer({ _, input, output ->
                while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                firstHead.complete(Unit)
                withTimeoutOrNull(500.milliseconds) { secondHead.await() }
                firstAnswered = true
                answer(input, output)
            }) { first ->
                rawServer({ _, input, output ->
                    while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                    secondWhileConnecting = !firstAnswered
                    secondHead.complete(Unit)
                    answer(input, output)
                }) { second ->
                    testClient(block = { install(WebSockets) }).use { c ->
                        coroutineScope {
                            val opened = CompletableDeferred<Unit>()
                            launch { c.webSocket("ws://127.0.0.1:$first/") { opened.await() } }
                            firstHead.await()
                            launch { c.webSocket("ws://127.0.0.1:$second/") { opened.complete(Unit) } }
                        }
                    }
                }
            }
            assertFalse(secondWhileConnecting, "a second connection to the address was in CONNECTING while the first was")
        }

    /**
     * A server that accepts the connection and never answers the handshake: the WebSocket fails with a connect timeout
     * (its opening handshake is part of connecting), and the next WebSocket to that address then proceeds. Before,
     * nothing bounded the wait for the 101, and every later WebSocket to the address waited behind it for ever.
     */
    @Test fun negative_stalledHandshakeTimesOutAndFreesTheAddress() =
        clientTest {
            rawServer({ index, input, output ->
                while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                if (index == 0) awaitCancellation()
                answer(input, output)
            }) { port ->
                testClient(
                    engine = { connectTimeout = 500.milliseconds },
                    block = { install(WebSockets) },
                ).use { c ->
                    val stalled = TimeSource.Monotonic.markNow()
                    assertFailsWith<ConnectTimeoutException> { c.webSocket("ws://127.0.0.1:$port/") {} }
                    assertTrue(stalled.elapsedNow() < 5.seconds, "the stalled handshake took ${stalled.elapsedNow()}")
                    var opened = false
                    c.webSocket("ws://127.0.0.1:$port/") { opened = true }
                    assertTrue(opened)
                    assertEquals(0, (c.engine as KuicksilverEngine).h1.webSocketConnecting.size(), "an entry outlived its WebSocket")
                }
            }
        }

    /**
     * The address is held only while a connection is CONNECTING, not while a WebSocket waits for a pool slot. With one
     * connection per route and a session holding it, two more WebSockets wait for the slot without holding the address;
     * cancelling one lets the other through once the session ends. Before, the first of them took the address and then
     * waited for the slot, and every further one queued behind it on the address.
     */
    @Test fun negative_waitingForAPoolSlotHoldsNoAddress() =
        clientTest {
            rawServer({ _, input, output ->
                while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                output.writeStringUtf8(SWITCHING)
                input.discard()
            }) { port ->
                testClient(
                    engine = { maxConnectionsPerRoute = 1 },
                    block = { install(WebSockets) },
                ).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    coroutineScope {
                        val firstOpen = CompletableDeferred<Unit>()
                        val endFirst = CompletableDeferred<Unit>()
                        val first =
                            launch {
                                c.webSocket("ws://127.0.0.1:$port/") {
                                    firstOpen.complete(Unit)
                                    endFirst.await()
                                }
                            }
                        firstOpen.await()
                        val second = launch { c.webSocket("ws://127.0.0.1:$port/") {} }
                        var thirdOpened = false
                        val third = launch { c.webSocket("ws://127.0.0.1:$port/") { thirdOpened = true } }
                        while (engine.h1.pool.waiterCount < 2) delay(5.milliseconds)
                        assertEquals(0, engine.h1.webSocketConnecting.size(), "a WebSocket waiting for a slot holds an address")
                        second.cancel()
                        endFirst.complete(Unit)
                        first.join()
                        third.join()
                        assertTrue(thirdOpened)
                    }
                    assertEquals(0, engine.h1.webSocketConnecting.size(), "an entry outlived its WebSocket")
                }
            }
        }

    /** A listener on 127.0.0.1 that runs [handler] per connection, [onAccept] first. */
    private suspend fun rawServer(
        handler: suspend (index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
        onAccept: (Int) -> Unit = {},
        block: suspend (Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind(InetSocketAddress("127.0.0.1", 0))
        try {
            coroutineScope {
                val server =
                    launch {
                        var index = 0
                        while (true) {
                            val s = listener.accept()
                            val i = index++
                            onAccept(i)
                            launch { s.use { runCatching { handler(i, it.openReadChannel(), it.openWriteChannel(autoFlush = true)) } } }
                        }
                    }
                withTimeout(20.seconds) { block((listener.localAddress as InetSocketAddress).port) }
                server.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /** The 101, then a Close frame (so the session ends without a timeout); then reads until the client closes. */
    private suspend fun answer(
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ) {
        output.writeStringUtf8(SWITCHING)
        output.writeFully(byteArrayOf(0x88.toByte(), 0x00))
        input.discard()
    }

    private companion object {
        const val SWITCHING =
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: unchecked\r\n\r\n"
    }
}
