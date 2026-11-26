// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.UdpProxy
import io.kuicksilver.http3.UdpProxyConfig
import io.kuicksilver.http3.UdpProxyTemplate
import io.kuicksilver.http3.UdpTargetFilter
import io.kuicksilver.ktor.server.connectUdp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramIo
import kotlinx.coroutines.flow.first
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The client engine's HTTP/3 through a CONNECT-UDP proxy (RFC 9298, MASQUE): a Ktor client, a Ktor server serving
 * `connectUdp(proxy)` and a Ktor target server, all on loopback. Only the test proxies may reach 127.0.0.1.
 */
@OptIn(ExperimentalAtomicApi::class)
class ClientConnectUdpProxyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A `proxy-authorization` the target received, if any (it never should). */
    @kotlin.concurrent.Volatile private var targetSawAuthorization: String? = null

    /** A proxy for these tests: loopback targets only, its sockets on 127.0.0.1. */
    private fun loopbackProxy() =
        UdpProxy(
            UdpProxyConfig(
                targetFilter = UdpTargetFilter.addresses("127.0.0.1"),
                refuseOwnAddresses = false, // proxy and target share this host's loopback by construction
                // no real ICMP Packet Too Big to 127.0.0.1: it would lower the kernel's cached path MTU there for later tests
                packetTooBig = false,
                socketFactory = { DatagramIo.open(InetSocketAddress("127.0.0.1", 0)) },
            ),
        )

    /** A target counting what it serves, and a proxy server in front of [proxy]; [block] gets both ports. */
    private suspend fun withProxyAndTarget(
        proxy: UdpProxy,
        requireAuthorization: String? = null,
        block: suspend (proxyPort: Int, targetPort: Int, served: AtomicInt) -> Unit,
    ) {
        val served = AtomicInt(0)
        targetSawAuthorization = null
        val (target, targetPort) =
            testServer {
                routing {
                    get("/") {
                        call.request.headers["proxy-authorization"]?.let { targetSawAuthorization = it }
                        served.incrementAndFetch()
                        call.respondText("hello over ${call.request.local.version}")
                    }
                }
            }
        val (proxyServer, proxyPort) =
            testServer(configure = { connectUdp = true }) {
                routing {
                    route("/") {
                        if (requireAuthorization != null) {
                            intercept(ApplicationCallPipeline.Plugins) {
                                if (call.request.headers["proxy-authorization"] != requireAuthorization) {
                                    call.respond(HttpStatusCode.ProxyAuthenticationRequired)
                                    finish()
                                }
                            }
                        }
                        connectUdp(proxy)
                    }
                }
            }
        try {
            block(proxyPort, targetPort, served)
        } finally {
            proxyServer.stop(100, 500)
            target.stop(100, 500)
        }
    }

    @Test fun http3ThroughTheProxy() =
        h3Test {
            val proxy = loopbackProxy()
            withProxyAndTarget(proxy) { proxyPort, targetPort, served ->
                val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort"))
                testClient(Http3Discovery.Auto, engine = { proxies { connectUdp = udp } }).use { c ->
                    val r = c.get("https://127.0.0.1:$targetPort/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("hello over HTTP/3", r.bodyAsText())
                    // the pooled tunnelled connection carries the next request too
                    assertEquals("hello over HTTP/3", c.get("https://127.0.0.1:$targetPort/").bodyAsText())
                }
                assertEquals(2, served.load())
                assertEquals(1, proxy.stats.tunnelsOpened)
                // closing the client closed the tunnelled connection, its tunnel and its connection to the proxy
                kotlinx.coroutines.withTimeout(10.seconds) { proxy.activeTunnels.first { it == 0 } }
                assertTrue(proxy.stats.toTargets > 0 && proxy.stats.fromTargets > 0, "${proxy.stats}")
            }
        }

    @Test fun joiningTheEngineJobWaitsForTheTunnelledConnectionsTrace() =
        h3Test {
            val proxy = loopbackProxy()
            withProxyAndTarget(proxy) { proxyPort, targetPort, _ ->
                val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort"))
                // the trace of the connection through the tunnel (the one to the target's port; the other goes to the proxy)
                // closes only on release: the engine's job must not complete before it
                val tunnelled = kotlin.concurrent.atomics.AtomicReference<String?>(null)
                val sink = CountingQlogSink(hold = { it == tunnelled.load() })
                val listener =
                    object : io.kuicksilver.quic.ConnectionListener {
                        override fun onOpened(connection: io.kuicksilver.quic.ConnectionInfo) {
                            if (connection.remoteAddress.port == targetPort) tunnelled.store(connection.id)
                        }
                    }

                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                val c =
                    testClient(Http3Discovery.Auto, engine = {
                        proxies { connectUdp = udp }
                        observability { qlog = sink }
                        observability { connectionListener = listener }
                    })
                val job = c.engine.coroutineContext[kotlinx.coroutines.Job]!!
                try {
                    assertEquals("hello over HTTP/3", c.get("https://127.0.0.1:$targetPort/").bodyAsText())
                    assertEquals(2, sink.opened.load())
                    assertTrue(tunnelled.load() != null, "the tunnelled connection was seen")
                    assertEquals(2, (c.engine as KuicksilverEngine).h3.endpointCountForTest, "the proxy hop's endpoint and the tunnel's")
                    c.close()
                    assertEquals(
                        null,
                        kotlinx.coroutines.withTimeoutOrNull(500.milliseconds) { job.join() },
                        "the join returned while the tunnelled connection's trace was still being closed",
                    )
                } finally {
                    sink.release()
                    c.close()
                }
                kotlinx.coroutines.withTimeout(10.seconds) { job.join() }
                assertEquals(2, sink.closed.load(), "every trace closed by the time join() returned")
                assertEquals(0, (c.engine as KuicksilverEngine).h3.endpointCountForTest, "every endpoint joined and forgotten")
            }
        }

    @Test fun credentialsGoToTheProxy() =
        h3Test {
            val proxy = loopbackProxy()
            val creds = ProxyCredentials("user", "secret")
            withProxyAndTarget(proxy, requireAuthorization = "Basic dXNlcjpzZWNyZXQ=") { proxyPort, targetPort, _ ->
                val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort"), creds)
                testClient(Http3Discovery.Auto, engine = { proxies { connectUdp = udp } }).use { c ->
                    assertEquals("hello over HTTP/3", c.get("https://127.0.0.1:$targetPort/").bodyAsText())
                }
                // the credentials went on the tunnel's CONNECT to the proxy, never inside the tunnel to the origin
                assertEquals(null, targetSawAuthorization)
                val noCreds = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort"))
                testClient(Http3Discovery.Auto, engine = { proxies { connectUdp = noCreds } }).use { c ->
                    val e = assertFailsWith<Http3Exception.ConnectRejected> { c.get("https://127.0.0.1:$targetPort/") }
                    assertEquals(407, e.status)
                }
            }
        }

    /** A refused tunnel fails the request: no fallback to TCP or a direct connection, which would leave the proxy out. */
    @Test fun negative_aRefusedTunnelNeverFallsBackToADirectConnection() =
        h3Test {
            val proxy = UdpProxy() // PublicOnly: refuses the loopback target
            withProxyAndTarget(proxy) { proxyPort, targetPort, served ->
                val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort"))
                testClient(Http3Discovery.Auto, engine = { proxies { connectUdp = udp } }).use { c ->
                    val e = assertFailsWith<Http3Exception.ConnectRejected> { c.get("https://127.0.0.1:$targetPort/") }
                    assertEquals(403, e.status)
                    assertEquals("proxy; error=destination_ip_prohibited", e.headers["proxy-status"])
                }
                assertEquals(0, served.load(), "the request reached the target without the proxy")
            }
        }

    /** HTTP/3 off (H1Only) cannot carry a request that must go through the CONNECT-UDP proxy: refused, never sent over TCP. */
    @Test fun negative_h1OnlyWithAConnectUdpProxyIsRefused() =
        h3Test {
            val proxy = loopbackProxy()
            withProxyAndTarget(proxy) { proxyPort, targetPort, served ->
                val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort"))
                testClient(null, engine = { proxies { connectUdp = udp } }).use { c ->
                    assertFailsWith<UnsupportedOperationException> { c.get("https://127.0.0.1:$targetPort/") }
                }
                assertEquals(0, served.load())
            }
        }

    /**
     * A tunnelled connection never resumes a session ticket a direct connection got (the origin could link the two, and
     * so the proxied client to its own address): tunnels keep the tickets of their proxy route apart.
     */
    @Test fun negative_tunnelsDoNotShareTicketsWithDirectConnections() =
        h3Test {
            val proxy = loopbackProxy()
            withProxyAndTarget(proxy) { proxyPort, targetPort, _ ->
                var tunnel = false
                val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort")) { tunnel }
                testClient(Http3Discovery.H3Only, engine = { proxies { connectUdp = udp } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    assertEquals("hello over HTTP/3", c.get("https://127.0.0.1:$targetPort/").bodyAsText()) // direct
                    assertEquals(null, engine.h3.tunnelTicketsForTest(udp.routeKey), "no tunnel yet")
                    tunnel = true
                    assertEquals("hello over HTTP/3", c.get("https://127.0.0.1:$targetPort/").bodyAsText()) // through the proxy
                    val tunnelled = engine.h3.tunnelTicketsForTest(udp.routeKey)
                    assertTrue(tunnelled != null && tunnelled !== engine.h3.directTicketsForTest, "a cache of the route's own")
                    assertTrue(engine.h3.tunnelTicketsUsedForTest === tunnelled, "the tunnelled endpoint was built with it")
                }
                assertEquals(1, proxy.stats.tunnelsOpened)
            }
        }

    /** WebTransport does not go through the tunnel: refused for such a URL unless its own switch says to connect directly. */
    @Test fun negative_webTransportIsRefusedWhereTheConnectUdpProxyApplies() =
        h3Test {
            val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:9"))
            testClient(Http3Discovery.Auto, engine = {
                proxies { connectUdp = udp }
                proxies { resolver = ProxyResolvers.None }
            }).use { c ->
                val e = assertFailsWith<UnsupportedOperationException> { c.webTransport("https://127.0.0.1:9/wt") }
                assertTrue("WebTransportProxyPolicy.BypassConnectUdpProxy" in (e.message ?: ""), e.message)
            }
            // the switch for HTTP and SOCKS proxies does not open the way past this one
            testClient(Http3Discovery.Auto, engine = {
                proxies { connectUdp = udp }
                proxies { resolver = ProxyResolvers.None }
                http3 { webTransport { proxyPolicy = WebTransportProxyPolicy.BypassHttpProxy } }
            }).use { c -> assertFailsWith<UnsupportedOperationException> { c.webTransport("https://127.0.0.1:9/wt") } }
        }

    /** A URL the proxy does not apply to takes the engine's usual path; the proxy sees nothing. */
    @Test fun aUrlTheProxyDoesNotApplyToGoesDirectly() =
        h3Test {
            val proxy = loopbackProxy()
            withProxyAndTarget(proxy) { proxyPort, targetPort, served ->
                val udp = ConnectUdpProxy(UdpProxyTemplate.wellKnown("127.0.0.1:$proxyPort")) { it.port != targetPort }
                testClient(Http3Discovery.H3Only, engine = { proxies { connectUdp = udp } }).use { c ->
                    assertEquals("hello over HTTP/3", c.get("https://127.0.0.1:$targetPort/").bodyAsText())
                }
                assertEquals(1, served.load())
                assertEquals(0, proxy.stats.tunnelsOpened)
            }
        }
}
