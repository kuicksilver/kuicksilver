// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

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
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

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

    /** A WebSocket to another address and port pair does not wait for the first one's handshake. */
    @Test fun handshakesToDifferentHostsDoNotWait() =
        clientTest {
            val heads = CompletableDeferred<Unit>()
            var count = 0
            val handler: suspend (Int, ByteReadChannel, ByteWriteChannel) -> Unit = { _, input, output ->
                while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) continue
                if (++count == 2) heads.complete(Unit)
                heads.await() // neither is answered before both handshakes arrived
                answer(input, output)
            }
            rawServer(handler) { first ->
                rawServer(handler) { second ->
                    testClient(block = { install(WebSockets) }).use { c ->
                        coroutineScope {
                            launch { c.webSocket("ws://127.0.0.1:$first/") { heads.await() } }
                            launch { c.webSocket("ws://127.0.0.1:$second/") { heads.await() } }
                        }
                    }
                }
            }
            assertEquals(2, count)
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
