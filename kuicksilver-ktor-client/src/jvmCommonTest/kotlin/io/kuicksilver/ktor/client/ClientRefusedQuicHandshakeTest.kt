// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.util.date.getTimeMillis
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.tls.ClientAuth
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * HTTP/3 wins, and only then does the server refuse the handshake: a UDP relay in front of the QUIC server lets the
 * server's datagrams through at once and holds every client datagram that follows the server's first answer for
 * [DELAY_MILLIS] (its Certificate and Finished, then its requests). The client's side of the handshake completes on the
 * server's flight (RFC 9001 section 4.1.1), so with `RaceHeadStart.NoRace` (TCP only after HTTP/3 failed) the HTTP/3
 * setup wins every time; the request goes out in 1-RTT, and the server's certificate_required comes after it. The server
 * processed nothing of it (RFC 9001 section 5.7), so the call goes over TCP, GET and POST alike, and fails there as over
 * TCP: one fallback whose cause is the alert's TransportClosed (CRYPTO_ERROR 0x0100 + 116). Before, a POST failed with that
 * TransportClosed.
 */
class ClientRefusedQuicHandshakeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Forwards UDP between one client and [upstream], the client's datagrams after the server's first held back [DELAY_MILLIS]. */
    private class DelayRelay(
        upstream: InetSocketAddress,
    ) {
        private val down: DatagramChannel = DatagramChannel.open().bind(InetSocketAddress("127.0.0.1", 0))
        private val up: DatagramChannel = DatagramChannel.open().bind(InetSocketAddress("127.0.0.1", 0))
        private val later = Executors.newSingleThreadScheduledExecutor()

        @Volatile private var client: SocketAddress? = null

        @Volatile private var serverAnswered = false

        val port: Int get() = (down.localAddress as InetSocketAddress).port

        private val toServer =
            thread(isDaemon = true, name = "delay-relay-up") {
                while (true) {
                    val b = ByteBuffer.allocate(2048)
                    client = runCatching { down.receive(b) }.getOrNull() ?: break
                    b.flip()
                    if (serverAnswered) {
                        // in order: one executor thread, every datagram the same delay
                        later.schedule({ runCatching { up.send(b, upstream) } }, DELAY_MILLIS, TimeUnit.MILLISECONDS)
                    } else if (runCatching { up.send(b, upstream) }.isFailure) {
                        break
                    }
                }
            }

        private val toClient =
            thread(isDaemon = true, name = "delay-relay-down") {
                val b = ByteBuffer.allocate(2048)
                while (true) {
                    b.clear()
                    runCatching { up.receive(b) }.getOrNull() ?: break
                    serverAnswered = true
                    b.flip()
                    val to = client ?: continue
                    if (runCatching { down.send(b, to) }.isFailure) break
                }
            }

        fun close() {
            later.shutdownNow()
            down.close()
            up.close()
            toServer.join()
            toClient.join()
        }
    }

    private val alert = "TLS alert received from the peer: certificate_required (116)"

    private fun refused(post: Boolean) =
        h3Test {
            val (server, port) =
                testServer(configure = { http2 { enabled = true } }, tls = {
                    tls {
                        clientAuth = ClientAuth.Required
                        clientTrust = ClientFixtures.trust
                    }
                }) {
                    routing {
                        get("/") { call.respondText("unreachable") }
                        post("/") { call.respondText("unreachable") }
                    }
                }
            val relay = DelayRelay(InetSocketAddress("127.0.0.1", port))
            try {
                val origin = "https://127.0.0.1:$port"
                val store = InMemoryAltSvcStore()
                store.put(origin, listOf(AltSvcEntry("h3", null, relay.port, getTimeMillis() + 3_600_000, false)))
                val races = AtomicReference(emptyList<HttpProtocolVersion>())
                val fallbacks = AtomicReference(emptyList<Throwable>())
                val e =
                    assertFails {
                        testClient(Http3Discovery.Auto, engine = {
                            http3 {
                                altSvcStore = store
                                expert { raceHeadStart = RaceHeadStart.NoRace }
                            }
                            observability {
                                eventListener =
                                    object : KuicksilverEventListener() {
                                        override fun raceEnded(
                                            request: HttpRequestData,
                                            winner: HttpProtocolVersion,
                                            headStart: kotlin.time.Duration,
                                            h3Failure: Throwable?,
                                        ) {
                                            while (true) {
                                                val l = races.load()
                                                if (races.compareAndSet(l, l + winner)) break
                                            }
                                        }

                                        override fun fallback(
                                            request: HttpRequestData,
                                            cause: Throwable,
                                        ) {
                                            while (true) {
                                                val l = fallbacks.load()
                                                if (fallbacks.compareAndSet(l, l + cause)) break
                                            }
                                        }
                                    }
                            }
                        }).use { c ->
                            if (post) c.post("$origin/") { setBody("a body") } else c.get("$origin/")
                        }
                    }
                val what = if (post) "POST" else "GET"
                assertEquals(listOf(HttpProtocolVersion.HTTP_3_0), races.load(), "$what: HTTP/3 won the race: $e")
                val fell = fallbacks.load().singleOrNull() ?: kotlin.test.fail("$what: one fallback, got ${fallbacks.load()}: $e")
                assertTrue(
                    fell is QuicException.ConnectionLost.TransportClosed && fell.code == 0x0174L,
                    "$what: the fallback's cause $fell",
                )
                assertIs<Http2Exception.ConnectionClosed>(e, "$what fails as over TCP: $e")
                assertEquals("the connection was lost: $alert", e.message, what)
            } finally {
                relay.close()
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun negative_aPostOnARefusedQuicHandshakeFailsAsOverTcp() = refused(post = true)

    @Test fun negative_aGetOnARefusedQuicHandshakeFailsAsOverTcp() = refused(post = false)

    private companion object {
        const val DELAY_MILLIS = 300L
    }
}
