// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.MemoryNet
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** HTTP/3 over 0-RTT (RFC 8470, RFC 9114 section 7.2.4.2, ADR-0015): early safe requests, gated unsafe ones, 425 and replay. */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class EarlyDataTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Seen(
        val method: String,
        val early: Boolean,
        val handshakeDone: Boolean,
    )

    private class Fixture(
        policy: Http3EarlyDataPolicy,
    ) : AutoCloseable {
        val net = MemoryNet()
        private val a = net.open(InetSocketAddress("10.0.0.1", 1111))
        private val b = net.open(InetSocketAddress("10.0.0.2", 443))

        @kotlin.concurrent.Volatile var last: Seen? = null
        val executions = AtomicInt(0)

        /** Server connections in accept order (one writer, the accept loop). */
        @kotlin.concurrent.Volatile var accepted: List<Http3Connection> = emptyList()

        /** Requests that came in 0-RTT and the server's gate held for the handshake (RFC 8470), over all connections. */
        val heldEarly: Int get() = accepted.sumOf { it.session.earlyHeldForHandshake.load() }

        // accept()/acceptRequest() end with an exception when the endpoint or a connection closes: on Kotlin/Native an
        // unhandled one would end the test process
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + kotlinx.coroutines.CoroutineExceptionHandler { _, _ -> })
        lateinit var server: Http3Endpoint
        lateinit var client: Http3Endpoint
        val serverSettings: Http3Settings = http3Settings { earlyData = policy }

        suspend fun start() {
            server =
                Http3Endpoint.bind(
                    b.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(H3Fixtures.server()).apply { earlyData = true }.build()
                            crypto = KslQuicCrypto
                            io = { b }
                        }.build(),
                    serverSettings,
                )
            client =
                Http3Endpoint.bind(
                    a.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = KslQuicCrypto
                            io = { a }
                        }.build(),
                )
            scope.launch {
                while (true) {
                    val c = server.accept()
                    accepted = accepted + c
                    scope.launch {
                        // each connection on its own: a closed one must not end the accept loop
                        while (true) {
                            val r = c.acceptRequest()
                            scope.launch {
                                r.body.readAllBytes()
                                if (r.method == "POST") executions.incrementAndFetch()
                                last = Seen(r.method, r.receivedEarly, c.quic.isHandshakeComplete)
                                r.respond(200, Http3Headers.Empty).also {
                                    it.output.writeFully("${r.method} ok".encodeToByteArray())
                                    it.finish()
                                }
                            }
                        }
                    }
                }
            }
        }

        /** A first connection that leaves the client endpoint a ticket. */
        suspend fun warmUp() {
            val c = client.connectEarly(server.localAddress, H3Fixtures.client())
            repeat(2) { assertEquals(200, c.request(get()).also { it.body.readAllBytes() }.status) }
            c.close()
        }

        fun get(early: Boolean = false) = Http3Request("GET", authority = "server.test", path = "/", allowEarlyData = early)

        fun post() = Http3Request("POST", authority = "server.test", path = "/order")

        override fun close() {
            scope.cancel()
            client.close()
            server.close()
        }
    }

    @Test fun earlyGetIsAnsweredIn0Rtt(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds // a round trip the 0-RTT request can beat
                    val c: Http3Connection = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    val r = c.request(f.get(early = true))
                    assertEquals("GET ok", r.body.readAllBytes().decodeToString())
                    c.quic.awaitHandshake()
                    assertEquals(true, c.quic.earlyDataAccepted)
                    val last = f.last!!
                    assertTrue(last.early && !last.handshakeDone, "the server ran the safe request before the handshake completed")
                }
            }
        }

    @Test fun unsafeRequestWaitsForHandshakeOnTheClient(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    assertEquals(
                        "POST ok",
                        c
                            .request(f.post())
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                    val last = f.last!!
                    assertTrue(!last.early && last.handshakeDone, "a POST never leaves the client in 0-RTT")
                }
            }
        }

    @Test fun negative_unsafeMethodNotProcessedInEarlyData(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    c.session.testSendUnsafeEarly = true // a client that ignores RFC 8470: POST in 0-RTT
                    assertEquals(
                        "POST ok",
                        c
                            .request(f.post())
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                    c.quic.awaitHandshake()
                    assertEquals(true, c.quic.earlyDataAccepted, "the server accepted the 0-RTT that carried the POST")
                    assertEquals(1, f.heldEarly, "the POST arrived in 0-RTT and the gate held it")
                    val last = f.last!!
                    assertTrue(!last.early && last.handshakeDone, "the early POST ran only after the handshake")
                    assertEquals(1, f.executions.load())
                    c.close()

                    // The replay, stopped by the HTTP/3 gate alone: an attacker on the path keeps a client's datagrams from the
                    // server and sends copies from its own address, so the replay register sees the ticket for the first time
                    // and admits it; the server's answers go to the attacker, who cannot complete the handshake.
                    f.warmUp() // a fresh ticket for the victim
                    f.net.delay = kotlin.time.Duration.ZERO // delivered at once, in order
                    val attacker = InetSocketAddress("10.0.0.9", 9999)
                    val fromClient = { from: InetSocketAddress, to: InetSocketAddress -> to.port == 443 && from.port == 1111 }
                    // the victim's packets are all long-header (its handshake never completes): told apart by their DCID
                    val dcid = { b: ByteArray -> if (b[0].toInt() and 0x80 != 0) b.copyOfRange(6, 6 + b[5]) else null }
                    var victim: ByteArray? = null
                    val isVictim = { from: InetSocketAddress, to: InetSocketAddress, b: ByteArray ->
                        fromClient(from, to) && dcid(b)?.contentEquals(victim) == true
                    }
                    f.net.tap = { from, to, bytes ->
                        if (fromClient(from, to) && victim == null) victim = dcid(bytes)
                        if (isVictim(from, to, bytes)) f.net.deliver(attacker, to, bytes)
                    }
                    f.net.drop = isVictim
                    val v = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    v.session.testSendUnsafeEarly = true
                    val pending = f.scope.launch { v.request(f.post()) }
                    while (f.heldEarly < 2) kotlinx.coroutines.yield()
                    assertEquals(
                        true,
                        f.accepted
                            .last()
                            .quic.earlyDataAccepted,
                        "the register admitted the replay: only the gate is left",
                    )
                    // a later request on a new connection is processed after the replayed datagrams (one loop, FIFO)
                    val d = f.client.connect(f.server.localAddress, H3Fixtures.client())
                    assertEquals(
                        "POST ok",
                        d
                            .request(f.post())
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                    assertEquals(2, f.executions.load(), "the replayed POST never ran: its handshake cannot complete")
                    pending.cancel()
                    v.close()
                }
            }
        }

    @Test fun reject425PolicyAndOneRetry(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.Reject425()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    c.session.testSendUnsafeEarly = true
                    val r = c.request(f.post())
                    assertEquals(200, r.status)
                    assertEquals("POST ok", r.body.readAllBytes().decodeToString())
                    assertEquals(1, c.session.early425Retries, "425 Too Early, then one retry after the handshake")
                    assertEquals(1, f.executions.load())
                }
            }
        }
}
