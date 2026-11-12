// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.plugin
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.url
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.updateAndGet
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
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
     * connection in a CONNECTING state"). Before, both connected and sent their handshakes at once. The first handshake is
     * held until the second WebSocket either waits for the address or reaches the server, whichever comes first: no window
     * of real time decides it.
     */
    @Test fun negative_secondHandshakeToTheSameAddressWaitsForTheFirst() =
        clientTest {
            val firstHead = CompletableDeferred<Unit>()
            val decided = CompletableDeferred<Unit>()
            val secondAccepted = CompletableDeferred<Unit>()
            rawServer({ index, input, output ->
                val key = input.readWebSocketKey()
                if (index == 0) {
                    firstHead.complete(Unit)
                    decided.await()
                }
                answer(key, input, output)
            }, onAccept = { if (it == 1) secondAccepted.complete(Unit) }) { port ->
                testClient(
                    engine = { resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) } },
                    block = { install(WebSockets) },
                ).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    coroutineScope {
                        val opened = CompletableDeferred<Unit>()
                        launch { c.webSocket("ws://a.test:$port/") { opened.await() } }
                        firstHead.await()
                        launch { c.webSocket("ws://b.test:$port/") { opened.complete(Unit) } }
                        assertEquals("waited", waitedOrConnected(engine, secondAccepted), "the second WebSocket to the address")
                        decided.complete(Unit)
                    }
                    assertEquals(0, engine.h1.webSocketConnecting.size(), "an entry outlived its WebSocket")
                }
            }
        }

    /**
     * Two WebSockets to one name whose resolutions answered differently (the first got the A records only, the second the
     * AAAA ones while A stalls) share no address key, but they share the name's: the second waits for the first. Before,
     * the keys were the answered addresses alone, so both were CONNECTING at once (RFC 6455 section 4.1 step 2).
     */
    @Test fun negative_twoWebSocketsToOneNameWithDifferentAnswersAreSerialized() =
        clientTest {
            val firstHead = CompletableDeferred<Unit>()
            val decided = CompletableDeferred<Unit>()
            val secondAccepted = CompletableDeferred<Unit>()
            val never = CompletableDeferred<Unit>()
            val v4Calls = kotlinx.coroutines.flow.MutableStateFlow(0)
            val v6Calls = kotlinx.coroutines.flow.MutableStateFlow(0)
            rawServer({ index, input, output ->
                val key = input.readWebSocketKey()
                if (index == 0) {
                    firstHead.complete(Unit)
                    decided.await()
                }
                answer(key, input, output)
            }, onAccept = { if (it == 1) secondAccepted.complete(Unit) }) { port ->
                testClient(
                    engine = {
                        connectTimeout = 5.seconds
                        familyResolverForTest = { _, v6 ->
                            if (v6) {
                                if (v6Calls.updateAndGet { it + 1 } == 1) {
                                    emptyList()
                                } else {
                                    listOf(TcpAddress(ByteArray(16).also { it[15] = 1 }, 0))
                                }
                            } else {
                                if (v4Calls.updateAndGet { it + 1 } > 1) never.await()
                                listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), 0))
                            }
                        }
                    },
                    block = { install(WebSockets) },
                ).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    coroutineScope {
                        val opened = CompletableDeferred<Unit>()
                        launch { c.webSocket("ws://same.test:$port/") { opened.await() } }
                        firstHead.await()
                        val second = launch { runCatching { c.webSocket("ws://same.test:$port/") { opened.complete(Unit) } } }
                        assertEquals("waited", waitedOrConnected(engine, secondAccepted), "the second WebSocket to the name")
                        decided.complete(Unit)
                        opened.complete(Unit)
                        second.cancel()
                    }
                }
            }
            never.complete(Unit)
        }

    private val loopback4 = TcpAddress(byteArrayOf(127, 0, 0, 1), 0)
    private val loopback6 = TcpAddress(ByteArray(16).also { it[15] = 1 }, 0)

    /**
     * The address a WebSocket's connection actually goes to is held, also when its keys did not name it: the AAAA answer
     * ([::1], where nothing listens) comes first and the keys are taken with it, then the A answer comes and the race
     * connects to 127.0.0.1. On every platform, Kotlin/Native included: the peer address is read from the socket.
     */
    @Test fun theConnectionsOwnAddressIsHeld() =
        clientTest {
            val head = CompletableDeferred<Unit>()
            val decided = CompletableDeferred<Unit>()
            val releaseA = CompletableDeferred<Unit>()
            rawServer({ _, input, output ->
                val key = input.readWebSocketKey()
                head.complete(Unit)
                decided.await()
                answer(key, input, output)
            }) { port ->
                testClient(
                    engine = {
                        familyResolverForTest = { _, v6 ->
                            if (v6) {
                                listOf(loopback6)
                            } else {
                                releaseA.await()
                                listOf(loopback4)
                            }
                        }
                    },
                    block = { install(WebSockets) },
                ).use { c ->
                    val connecting = (c.engine as KuicksilverEngine).h1.webSocketConnecting
                    coroutineScope {
                        launch { c.webSocket("ws://a.wild.test:$port/") {} }
                        withTimeout(10.seconds) { connecting.acquiredForTest.first { it >= 1 } }
                        assertFalse("address 127.0.0.1" in connecting.keysForTest(), "${connecting.keysForTest()}")
                        releaseA.complete(Unit)
                        withTimeout(10.seconds) { head.await() }
                        val keys = connecting.keysForTest()
                        assertTrue("address 127.0.0.1" in keys && "name a.wild.test" in keys, "$keys")
                        decided.complete(Unit)
                    }
                    assertEquals(0, connecting.size())
                }
            }
        }

    /**
     * A WebSocket whose connection went to an address another WebSocket holds (here one to another name, CONNECTING to
     * 127.0.0.1) gives the connection back to the pool and waits for every key, that address too; then it takes the same
     * connection again. Nothing leaks: two TCP connections in all, the pool empty at the end.
     */
    @Test fun negative_aConnectionToAnAddressAnotherWebSocketHoldsGoesBackAndWaits() =
        clientTest {
            val firstHead = CompletableDeferred<Unit>()
            val decided = CompletableDeferred<Unit>()
            val releaseA = CompletableDeferred<Unit>()
            val handshakes = kotlinx.coroutines.flow.MutableStateFlow(0)
            val accepted = kotlinx.coroutines.flow.MutableStateFlow(0)
            rawServer({ index, input, output ->
                val key = input.readWebSocketKey()
                handshakes.updateAndGet { it + 1 }
                if (index == 0) {
                    firstHead.complete(Unit)
                    decided.await()
                }
                answer(key, input, output)
            }, onAccept = { accepted.updateAndGet { it + 1 } }) { port ->
                testClient(
                    engine = {
                        familyResolverForTest = { name, v6 ->
                            when {
                                name == "b.wild.test" -> {
                                    if (v6) emptyList() else listOf(loopback4)
                                }

                                v6 -> {
                                    listOf(loopback6)
                                }

                                else -> {
                                    releaseA.await()
                                    listOf(loopback4)
                                }
                            }
                        }
                    },
                    block = { install(WebSockets) },
                ).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val connecting = engine.h1.webSocketConnecting
                    coroutineScope {
                        val opened = CompletableDeferred<Unit>()
                        launch { c.webSocket("ws://b.wild.test:$port/") { opened.await() } }
                        withTimeout(10.seconds) { firstHead.await() }
                        launch { c.webSocket("ws://a.wild.test:$port/") { opened.complete(Unit) } }
                        withTimeout(10.seconds) { connecting.acquiredForTest.first { it >= 2 } }
                        releaseA.complete(Unit)
                        withTimeout(10.seconds) { connecting.waitsForTest.first { it >= 1 } }
                        assertEquals(1, handshakes.value, "the second handshake went out while the address was held")
                        withTimeout(10.seconds) { accepted.first { it >= 2 } }
                        decided.complete(Unit)
                    }
                    assertEquals(2, handshakes.value)
                    assertEquals(2, accepted.value, "the connection given back was not used again")
                    assertEquals(0, engine.h1.pool.liveCount, "a connection outlived its WebSocket")
                    assertEquals(0, connecting.size())
                }
            }
        }

    /**
     * The unit is the IP address: "If multiple connections to the same IP address are attempted simultaneously, the client
     * MUST serialize them" (RFC 6455 section 4.1, step 2). A WebSocket to another port of the address waits too. Before,
     * the keys were `ip:port`, and both handshakes were in flight at once.
     */
    @Test fun negative_handshakeToAnotherPortOfTheAddressWaits() =
        clientTest {
            val firstHead = CompletableDeferred<Unit>()
            val decided = CompletableDeferred<Unit>()
            val secondHead = CompletableDeferred<Unit>()
            rawServer({ _, input, output ->
                val key = input.readWebSocketKey()
                firstHead.complete(Unit)
                decided.await()
                answer(key, input, output)
            }) { first ->
                rawServer({ _, input, output ->
                    val key = input.readWebSocketKey()
                    secondHead.complete(Unit)
                    answer(key, input, output)
                }) { second ->
                    testClient(block = { install(WebSockets) }).use { c ->
                        coroutineScope {
                            val opened = CompletableDeferred<Unit>()
                            launch { c.webSocket("ws://127.0.0.1:$first/") { opened.await() } }
                            firstHead.await()
                            launch { c.webSocket("ws://127.0.0.1:$second/") { opened.complete(Unit) } }
                            assertEquals(
                                "waited",
                                waitedOrConnected(c.engine as KuicksilverEngine, secondHead),
                                "the WebSocket to another port",
                            )
                            decided.complete(Unit)
                        }
                    }
                }
            }
        }

    /**
     * Two distinct addresses do not wait for each other (review 2026-10-28 N6: the key is the address, so a regression to
     * one lock for every WebSocket would show here): the second handshake reaches its server while the first is unanswered.
     */
    @Test fun handshakesToTwoAddressesDoNotWait() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val v6 = runCatching { aSocket(selector).tcp().bind("::1", 0).close() }
            selector.close()
            v6.onFailure {
                println("handshakesToTwoAddressesDoNotWait skipped: needs an IPv6 loopback ($it)")
                return@clientTest
            }
            val firstHead = CompletableDeferred<Unit>()
            val secondHead = CompletableDeferred<Unit>()
            rawServer({ _, input, output ->
                val key = input.readWebSocketKey()
                firstHead.complete(Unit)
                secondHead.await()
                answer(key, input, output)
            }) { first ->
                // the IPv6 loopback: on every host the tests run on, unlike 127.0.0.2 (not routed on macOS by default)
                rawServer({ _, input, output ->
                    val key = input.readWebSocketKey()
                    secondHead.complete(Unit)
                    answer(key, input, output)
                }, host = "::1") { second ->
                    testClient(block = { install(WebSockets) }).use { c ->
                        coroutineScope {
                            launch { c.webSocket("ws://127.0.0.1:$first/") {} }
                            firstHead.await()
                            launch { c.webSocket("ws://[::1]:$second/") {} }
                        }
                        assertEquals(
                            0,
                            (c.engine as KuicksilverEngine)
                                .h1.webSocketConnecting.waitsForTest.value,
                            "a WebSocket waited",
                        )
                    }
                }
            }
        }

    /**
     * The wait for the address is not connecting time and takes nothing from the pool (review 2026-10-28 R1 and review S2):
     * a WebSocket waiting for the address (held here by the test, as another WebSocket's CONNECTING connection holds it)
     * has neither a pool permit nor a connection, so no connect timeout runs for it and it cannot starve other requests;
     * once the address is free it connects within its own connect timeout. Before R1 the queue counted against the connect timeout;
     * after R1 and before S2 the waiting WebSocket held a pool permit for as long as it waited.
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun aWebSocketWaitingForTheAddressHoldsNothingOfThePool() =
        clientTest {
            val accepted = kotlin.concurrent.atomics.AtomicInt(0)
            rawServer({ _, input, output ->
                val key = input.readWebSocketKey()
                answer(key, input, output)
            }, onAccept = { accepted.addAndFetch(1) }) { port ->
                testClient(
                    engine = { connectTimeout = 5.seconds },
                    block = { install(WebSockets) },
                ).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val connecting = engine.h1.webSocketConnecting
                    val other = connecting.acquire(listOf("address 127.0.0.1"))
                    coroutineScope {
                        var opened = false
                        val ws = launch { c.webSocket("ws://127.0.0.1:$port/") { opened = true } }
                        withTimeout(10.seconds) { connecting.waitsForTest.first { it >= 1 } }
                        assertEquals(0, engine.h1.pool.liveCount, "a WebSocket waiting for the address holds a pool permit or connection")
                        assertEquals(0, engine.h1.pool.queuedForTest.value, "a WebSocket waiting for the address waits for the pool too")
                        assertEquals(0, accepted.load(), "a WebSocket waiting for the address connected")
                        other.release()
                        ws.join()
                        assertTrue(opened, "the WebSocket did not open once the address was free")
                    }
                    assertEquals(0, connecting.size(), "an entry outlived its WebSocket")
                }
            }
        }

    /**
     * A WebSocket whose connection the h3/h1 race already opened does not wait for its keys holding it (review S2 of
     * 7de616bf): with the address held by another WebSocket, the race's connection goes back to the pool (idle, not held)
     * and the WebSocket waits for the address through the pool path, holding nothing; once the address is free it takes the
     * pooled connection.
     */
    @OptIn(io.ktor.utils.io.InternalAPI::class)
    @Test
    fun aRaceOpenedConnectionIsNotHeldWhileItsWebSocketWaitsForTheAddress() =
        clientTest {
            rawServer({ _, input, output ->
                val key = input.readWebSocketKey()
                output.writeStringUtf8(switchingProtocols(key))
                input.discard()
            }) { port ->
                testClient(block = { install(WebSockets) }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val data =
                        io.ktor.client.request
                            .HttpRequestBuilder()
                            .apply {
                                url("ws://127.0.0.1:$port/")
                                attributes.put(io.ktor.client.plugins.websocket.WEBSOCKETS_KEY, c.plugin(WebSockets))
                            }.build()
                    val opened = engine.h1.open(data)
                    val other = engine.h1.webSocketConnecting.acquire(listOf("address 127.0.0.1"))
                    coroutineScope {
                        val exchange = async { engine.h1.execute(data, coroutineContext, opened) }
                        withTimeout(10.seconds) {
                            engine.h1.webSocketConnecting.waitsForTest
                                .first { it >= 1 }
                        }
                        assertEquals(1, engine.h1.raceConnectionsReturnedForTest, "the race's connection was kept while waiting")
                        assertEquals(1, engine.h1.pool.idleCount, "the race's connection is not idle in the pool")
                        other.release()
                        // the WebSocket then takes the address and the pooled connection: the race's connection, reused
                        withTimeoutOrNull(10.seconds) { while (engine.h1.pool.idleCount != 0) kotlinx.coroutines.yield() }
                            ?: error("the WebSocket did not take the pooled connection once the address was free")
                        exchange.cancel()
                    }
                }
            }
        }

    /**
     * A server that accepts the connection and never answers the handshake: the WebSocket fails with a connect timeout
     * (its opening handshake is part of connecting), and the next WebSocket to that address then proceeds. Before,
     * nothing bounded the wait for the 101, and every later WebSocket to the address waited behind it for ever.
     */
    @Test fun negative_stalledHandshakeTimesOutAndFreesTheAddress() =
        clientTest {
            rawServer({ index, input, output ->
                val key = input.readWebSocketKey()
                if (index == 0) awaitCancellation()
                answer(key, input, output)
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
     * The name resolution a WebSocket runs before it takes the address counts against the connect timeout, as a request's
     * resolution inside connecting does: resolving, then a TLS handshake the server never answers, fail together within one
     * connect timeout. Before, the resolution had a connect timeout of its own and the connection a fresh one after it.
     */
    @Test fun negative_aWebSocketsResolutionSharesTheConnectTimeout() =
        clientTest {
            rawServer({ _, input, _ -> input.discard() }) { port ->
                testClient(
                    engine = {
                        connectTimeout = 2.seconds
                        resolverForTest = { _, p ->
                            kotlinx.coroutines.delay(1500)
                            listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p))
                        }
                    },
                    block = { install(WebSockets) },
                ).use { c ->
                    val started = TimeSource.Monotonic.markNow()
                    assertFailsWith<ConnectTimeoutException> { c.webSocket("wss://ws.test:$port/") {} }
                    // one connect timeout (2 s) and some slack; two in series took 3.5 s
                    assertTrue(started.elapsedNow() < 2900.milliseconds, "resolving and connecting took ${started.elapsedNow()}")
                }
            }
        }

    /**
     * A WebSocket takes the address first and then waits for the pool (review S2: a pool permit is never held while
     * waiting for the address). With one connection per route and a session holding it, the second WebSocket holds the
     * address while it waits for the slot, the third waits for the address; cancelling the second lets the third through
     * once the session ends, and nothing is left held.
     */
    @Test fun aWebSocketWaitingForAPoolSlotHoldsItsAddressOnly() =
        clientTest {
            rawServer({ _, input, output ->
                val key = input.readWebSocketKey()
                output.writeStringUtf8(switchingProtocols(key))
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
                        withTimeout(10.seconds) {
                            engine.h1.pool.queuedForTest
                                .first { it >= 1 }
                        }
                        var thirdOpened = false
                        val third = launch { c.webSocket("ws://127.0.0.1:$port/") { thirdOpened = true } }
                        withTimeout(10.seconds) {
                            engine.h1.webSocketConnecting.waitsForTest
                                .first { it >= 1 }
                        }
                        assertEquals(1, engine.h1.pool.waiterCount, "only the WebSocket holding the address waits for the pool")
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

    /**
     * Whether the second WebSocket waited for the address ([WebSocketConnecting.waitsForTest]) or reached its server
     * ([accepted]) first; each is an event that happens, so whichever comes first decides, without a window of real time.
     */
    private suspend fun waitedOrConnected(
        engine: KuicksilverEngine,
        accepted: CompletableDeferred<Unit>,
    ): String =
        withTimeout(10.seconds) {
            coroutineScope {
                val waited =
                    async {
                        engine.h1.webSocketConnecting.waitsForTest
                            .first { it >= 1 }
                    }
                select {
                    waited.onAwait { "waited" }
                    accepted.onAwait { "connected" }
                }.also { waited.cancel() }
            }
        }

    /** A listener on [host] (127.0.0.1) that runs [handler] per connection, [onAccept] first. */
    private suspend fun rawServer(
        handler: suspend (index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
        onAccept: (Int) -> Unit = {},
        host: String = "127.0.0.1",
        block: suspend (Int) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, host, 0)
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
        key: String?,
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ) {
        output.writeStringUtf8(switchingProtocols(key))
        output.writeFully(byteArrayOf(0x88.toByte(), 0x00))
        input.discard()
    }
}
