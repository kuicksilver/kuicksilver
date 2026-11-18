// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.kuicksilver.http3.CapsuleProtocol
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.UdpProxy
import io.kuicksilver.http3.UdpProxyConfig
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.http3.UdpTargetFilter
import io.kuicksilver.http3.connectUdp
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.PacketBatch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** CONNECT-UDP (RFC 9298) through Ktor routing: `connectUdp(proxy)` on an engine with `connectUdp = true`, over real UDP on loopback. */
class ServerConnectUdpTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val loopback = InetSocketAddress("127.0.0.1", 0)
    private val template = UdpProxyTemplate.wellKnown("server.test")

    /** A proxy that may reach 127.0.0.1 only (tests), on sockets bound there. */
    private fun loopbackProxy() =
        UdpProxy(UdpProxyConfig(targetFilter = UdpTargetFilter.addresses("127.0.0.1"), socketFactory = { DatagramIo.open(loopback) }))

    private suspend fun <T> h3(
        port: Int,
        block: suspend (Http3Connection) -> T,
    ): T {
        val ep = Http3Endpoint.bind(loopback)
        try {
            val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
            try {
                return block(c)
            } finally {
                c.close()
            }
        } finally {
            ep.close()
        }
    }

    /** A UDP target on loopback that answers each payload with "echo:" and the payload, until [io] is closed. */
    private fun CoroutineScope.echo(io: DatagramIo): Job =
        launch {
            PacketBatch(4, 1500).use { b ->
                while (true) {
                    b.count = 0
                    try {
                        io.receive(b)
                    } catch (_: Exception) {
                        return@launch // the target was closed
                    }
                    for (i in 0 until b.count) {
                        val answer = "echo:".encodeToByteArray() + b.buffer(i).toByteArray(b.length(i))
                        b.buffer(i).copyFrom(answer, 0, 0, answer.size)
                        b.setLength(i, answer.size)
                    }
                    io.send(b)
                }
            }
        }

    @Test fun tunnelThroughTheRoute() =
        h3ServerTest {
            val (server, port) = tlsServer({ connectUdp = true }) { routing { connectUdp(loopbackProxy()) } }
            val target = DatagramIo.open(loopback)
            try {
                coroutineScope {
                    val echoing = echo(target)
                    h3(port) { c ->
                        val tunnel = c.connectUdp(template, "127.0.0.1", target.localAddress.port)
                        assertEquals(true, CapsuleProtocol.isEnabled(tunnel.stream.stream.headers))
                        tunnel.send("ktor".encodeToByteArray())
                        assertContentEquals("echo:ktor".encodeToByteArray(), withTimeout(10.seconds) { tunnel.payloads.first() })
                        tunnel.close()
                    }
                    echoing.cancel()
                }
            } finally {
                target.close()
                server.stopSuspend(100, 1000)
            }
        }

    /** The default proxy refuses loopback (RFC 9298 section 7): 403 with `destination_ip_prohibited`, through the route. */
    @Test fun negative_defaultProxyRefusesLoopbackThroughTheRoute() =
        h3ServerTest {
            val (server, port) = tlsServer({ connectUdp = true }) { routing { connectUdp() } }
            try {
                h3(port) { c ->
                    val e = assertFailsWith<Http3Exception.ConnectRejected> { c.connectUdp(template, "127.0.0.1", 9) }
                    assertEquals(403, e.status)
                    assertEquals("proxy; error=destination_ip_prohibited", e.headers["proxy-status"])
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** An authentication check in front of the route answers first; the proxy never runs. */
    @Test fun negative_aRefusalBeforeTheRouteGoesOutAsItIs() =
        h3ServerTest {
            val proxy = loopbackProxy()
            val (server, port) =
                tlsServer({ connectUdp = true }) {
                    routing {
                        route("/") {
                            intercept(io.ktor.server.application.ApplicationCallPipeline.Plugins) {
                                if (call.request.headers["proxy-authorization"] != "Bearer ok") {
                                    call.respond(HttpStatusCode.ProxyAuthenticationRequired)
                                    finish()
                                }
                            }
                            connectUdp(proxy)
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val e = assertFailsWith<Http3Exception.ConnectRejected> { c.connectUdp(template, "127.0.0.1", 9) }
                    assertEquals(407, e.status)
                    val ok = c.connectUdp(template, "127.0.0.1", 9, Http3Headers(listOf("proxy-authorization" to "Bearer ok")))
                    ok.close()
                }
                assertEquals(1, proxy.stats.tunnelsOpened)
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** Without `connectUdp = true` the engine answers a CONNECT-UDP with 501 (RFC 9220 section 3), whatever the routes. */
    @Test fun negative_engineWithoutConnectUdpAnswers501() =
        h3ServerTest {
            val (server, port) = tlsServer({ webSocketsOverHttp3 = true }) { routing { connectUdp(loopbackProxy()) } }
            try {
                h3(port) { c ->
                    assertEquals(501, assertFailsWith<Http3Exception.ConnectRejected> { c.connectUdp(template, "127.0.0.1", 9) }.status)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** A 2xx from a route other than `connectUdp` would claim a tunnel nobody opened: it goes out as 501. */
    @Test fun negative_otherRoutesTwoHundredIs501() =
        h3ServerTest {
            val (server, port) =
                tlsServer({ connectUdp = true }) {
                    routing { route("{...}", HttpMethod("CONNECT")) { handle { call.respondText("not a tunnel") } } }
                }
            try {
                h3(port) { c ->
                    assertEquals(501, assertFailsWith<Http3Exception.ConnectRejected> { c.connectUdp(template, "127.0.0.1", 9) }.status)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** No route takes a CONNECT-UDP request: Ktor's 404. */
    @Test fun noRouteIs404() =
        h3ServerTest {
            val (server, port) = tlsServer({ connectUdp = true }) { routing { route("/x") { handle { call.respondText("x") } } } }
            try {
                h3(port) { c ->
                    assertEquals(404, assertFailsWith<Http3Exception.ConnectRejected> { c.connectUdp(template, "127.0.0.1", 9) }.status)
                    // an ordinary request still works
                    assertEquals(200, c.request(http3Request("GET", "server.test", "/x")).status)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }
}
