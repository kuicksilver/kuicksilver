// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.ipLiteral
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The endpoint an HTTP/3 connection leaves from: one bound to the loopback address of its family for a loopback server
 * (127.0.0.1, ::1), the shared wildcard one otherwise. On the wildcard address a socket shares its port with one another
 * local process holds on the loopback address (macOS), and that process got the server's replies.
 */
class ClientH3EndpointChoiceTest {
    private suspend fun chosenFor(
        host: String,
        bind: String,
    ): List<Pair<String, String>> {
        val server =
            io.ktor.server.engine.embeddedServer(io.kuicksilver.ktor.server.Kuicksilver, configure = {
                tlsConnector(ClientFixtures.identity()) {
                    this.host = bind
                    port = 0
                }
            }) { routing { get("/") { call.respondText("ok") } } }
        if (runCatching { server.startSuspend(false) }.isFailure) return emptyList() // no IPv6 loopback here
        try {
            val port =
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            val chosen = ArrayList<Pair<String, String>>()
            testClient(Http3DiscoveryMode.H3Only).use { c ->
                (c.engine as KuicksilverEngine).h3.endpointChosenForTest = { remote, ep ->
                    chosen += remote.ipLiteral() to ep.localAddress.ipLiteral()
                }
                val r = c.get("https://$host:$port/")
                assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                assertEquals("ok", r.bodyAsText())
                // the same destination again: the same endpoint, the pooled connection
                assertEquals("ok", c.get("https://$host:$port/").bodyAsText())
            }
            return chosen
        } finally {
            server.stop(100, 500)
        }
    }

    @Test fun anIpv4LoopbackServerIsReachedFromLoopback() =
        h3Test {
            val chosen = chosenFor("127.0.0.1", "127.0.0.1")
            assertEquals(listOf("127.0.0.1" to "127.0.0.1"), chosen)
        }

    @Test fun anIpv6LoopbackServerIsReachedFromLoopback() =
        h3Test {
            val chosen = chosenFor("[::1]", "::1")
            if (chosen.isEmpty()) {
                println("anIpv6LoopbackServerIsReachedFromLoopback skipped: needs an IPv6 loopback")
                return@h3Test
            }
            assertEquals(listOf("::1" to "::1"), chosen)
        }

    /** Any other destination keeps the shared endpoint on the wildcard address (here a documentation address, never answered). */
    @Test fun negative_aServerElsewhereIsReachedFromTheWildcard() =
        h3Test {
            val chosen = ArrayList<Pair<String, String>>()
            testClient(Http3DiscoveryMode.H3Only, engine = { connectTimeout = 300.milliseconds }).use { c ->
                (c.engine as KuicksilverEngine).h3.endpointChosenForTest = { remote, ep ->
                    chosen += remote.ipLiteral() to ep.localAddress.ipLiteral()
                }
                assertFails { c.get("https://192.0.2.1:443/") }
            }
            assertTrue(chosen.isNotEmpty(), "an attempt was made")
            assertTrue(chosen.all { it == "192.0.2.1" to "0.0.0.0" }, "$chosen")
        }

    /**
     * Closes the client while the endpoint for [host] is being bound, at the step [stored] names (before the pool stores it,
     * or after the store and before it reads `closed`), and checks that the pool keeps no endpoint and the one bound is
     * closed. Nothing may leave the client: no connection is attempted, and a UDP port this test binds (the loopback
     * destination, and the target of the closed endpoint's connect) receives nothing but the test's own marker. False when
     * the sink could not be bound (no IPv6 loopback here); once it is, the pool's endpoint must be bound too, on the same
     * kind of socket, or the case fails.
     *
     * The sink and the marker are [DatagramIo] sockets, not ktor-network ones: on Native, ktor-network binds `::1` as the
     * wildcard `::` and its datagrams to `::1` never arrive (KTOR-10017, see `KtorDatagramIo`), so the ::1 case would bind a
     * wildcard port and wait for a marker that never comes.
     */
    private suspend fun closeDuringTheBind(
        host: String,
        stored: Boolean,
    ): Boolean {
        val sinkHost = if (host == "[::1]") "::1" else "127.0.0.1"
        val case = "$host, closed ${if (stored) "after" else "before"} the store"
        val sink = runCatching { DatagramIo.open(InetSocketAddress(sinkHost, 0)) }.getOrNull() ?: return false
        sink.use {
            val sinkAddress = InetSocketAddress(sinkHost, sink.localAddress.port)
            // the loopback cases aim at the sink; 192.0.2.1 is never sent to (the bind fails before any connect)
            val target = if (host == "192.0.2.1") "192.0.2.1:443" else "$host:${sinkAddress.port}"
            var bound: Http3Endpoint? = null
            var attempts = 0
            val c = testClient(Http3DiscoveryMode.H3Only, engine = { connectTimeout = 300.milliseconds })
            val pool = (c.engine as KuicksilverEngine).h3
            pool.endpointChosenForTest = { _, _ -> attempts++ }
            pool.endpointBindStepForTest = { ep, step ->
                if (step == stored) {
                    bound = ep
                    pool.close() // the client closes right now
                }
            }
            runCatching { c.get("https://$target/") }
            c.close()
            val ep = bound ?: fail("$case: no endpoint was bound")
            assertEquals(0, attempts, "$case: no connection is attempted")
            assertFalse(pool.endpointBoundForTest, "$case: the pool holds no endpoint")
            val tls = (c.engine as KuicksilverEngine).config.tlsConfigFor("server.test", listOf(Http3Endpoint.H3))
            assertFailsWith<QuicException.EndpointClosing>("$case: the endpoint bound during the close is closed") {
                withTimeout(5.seconds) { ep.connect(sinkAddress, tls) }
            }
            // the test's own marker, sent last: a datagram of the client would have been queued at the sink before it
            DatagramIo.open(InetSocketAddress(sinkHost, 0)).use { marker ->
                PacketBatch(1).use { out ->
                    out.buffer(0)[0] = 42
                    out.setLength(0, 1)
                    out.setAddress(0, sinkAddress)
                    assertEquals(1, marker.send(out), "$case: the marker left")
                }
            }
            PacketBatch(1).use { first ->
                withTimeout(5.seconds) { sink.receive(first) }
                val got = first.buffer(0).toByteArray(first.length(0))
                assertContentEquals(byteArrayOf(42), got, "$case: the sink received a datagram of the client")
            }
        }
        return true
    }

    /**
     * A client closed while an endpoint is being bound keeps no endpoint: the close, which takes no lock, either finds the
     * endpoint stored or the bind finds the client closed. Here the close lands after the store, before the bind reads
     * `closed`, and finds the endpoint. Each endpoint the pool keeps: the wildcard one, 127.0.0.1 and ::1 (where there is an
     * IPv6 loopback).
     */
    @Test fun negative_aCloseDuringTheBindLeavesNoEndpoint() =
        h3Test {
            assertTrue(closeDuringTheBind("192.0.2.1", stored = true), "the wildcard endpoint is bound")
            assertTrue(closeDuringTheBind("127.0.0.1", stored = true), "the IPv4 loopback endpoint is bound")
            if (!closeDuringTheBind("[::1]", stored = true)) println("the ::1 case skipped: needs an IPv6 loopback")
        }

    /**
     * A close that lands after the bind passed its first `closed` check and before the store finds nothing: the bind sees
     * `closed` after storing, closes the endpoint and clears the field it stored it in, for each endpoint the pool keeps.
     * Before, the bind read `closed` first and stored after it, so a close between the read and the store found nothing and
     * the endpoint stayed open.
     */
    @Test fun negative_aCloseBeforeTheStoreLeavesNoEndpoint() =
        h3Test {
            assertTrue(closeDuringTheBind("192.0.2.1", stored = false), "the wildcard endpoint is bound")
            assertTrue(closeDuringTheBind("127.0.0.1", stored = false), "the IPv4 loopback endpoint is bound")
            if (!closeDuringTheBind("[::1]", stored = false)) println("the ::1 case skipped: needs an IPv6 loopback")
        }
}
