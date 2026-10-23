// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** `ProxyResolvers.System` on the JVM is `ProxySelector.getDefault()`, the engine's default resolver. */
class SystemProxyJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun systemResolverFollowsDefaultProxySelector() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("via the selector") } } }
            val previous = ProxySelector.getDefault()
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    val asked = ArrayList<URI>()
                    ProxySelector.setDefault(
                        object : ProxySelector() {
                            override fun select(uri: URI): List<Proxy> {
                                asked += uri
                                return listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved("127.0.0.1", proxyPort)))
                            }

                            override fun connectFailed(
                                uri: URI?,
                                sa: SocketAddress?,
                                ioe: IOException?,
                            ) {}
                        },
                    )
                    testClient(Http3DiscoveryMode.Auto).use { c ->
                        // the default proxyResolver
                        assertEquals("via the selector", c.get("https://server.test:$port/").bodyAsText())
                        assertEquals("CONNECT server.test:$port HTTP/1.1", head().first())
                        assertEquals(URI("https://server.test:$port/"), asked.single())
                        // loopback never asks the selector
                        runCatching { c.get("https://127.0.0.1:1/") }
                        assertEquals(1, asked.size)
                    }
                }
            } finally {
                ProxySelector.setDefault(previous)
                server.stop(100, 500)
            }
        }

    /** A `ProxySelector` that blocks (waiting on the network) fails the request at the connect timeout. */
    @Test fun negative_blockingSelectorFailsAtConnectTimeout() =
        clientTest {
            val previous = ProxySelector.getDefault()
            val release = java.util.concurrent.CountDownLatch(1)
            try {
                ProxySelector.setDefault(
                    object : ProxySelector() {
                        override fun select(uri: URI): List<Proxy> {
                            release.await()
                            return listOf(Proxy.NO_PROXY)
                        }

                        override fun connectFailed(
                            uri: URI?,
                            sa: SocketAddress?,
                            ioe: IOException?,
                        ) {}
                    },
                )
                testClient(engine = { connectTimeout = kotlin.time.Duration.parse("300ms") }).use { c ->
                    val e = kotlin.test.assertFailsWith<ProxyException> { c.get("https://blocked.test/") }
                    kotlin.test.assertTrue("connect timeout" in e.message!!, e.message)
                }
            } finally {
                release.countDown()
                ProxySelector.setDefault(previous)
            }
        }
}
