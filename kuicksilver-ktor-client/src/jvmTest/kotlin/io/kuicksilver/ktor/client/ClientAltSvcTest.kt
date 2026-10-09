// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class ClientAltSvcTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun autoUpgradesToH3AfterAltSvc() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("used=${call.request.headers["Alt-Used"]}") } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { c ->
                    val first = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, first.version)
                    assertEquals("used=null", first.bodyAsText())
                    // the second request races HTTP/3 against the pooled HTTP/1.1 connection (no head start on a network where QUIC
                    // was not seen working yet): HTTP/1.1 wins on loopback, the QUIC connection set up meanwhile serves the next ones
                    c.get("https://127.0.0.1:$port/").bodyAsText()
                    val engine = c.engine as KuicksilverEngine
                    kotlinx.coroutines.withTimeout(5.seconds) {
                        while (!engine.hasH3Connection(io.ktor.http.Url("https://127.0.0.1:$port/"))) kotlinx.coroutines.delay(20)
                    }
                    val third = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, third.version)
                    assertEquals("used=127.0.0.1:$port", third.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun plainHttpAltSvcIgnored() =
        clientTest {
            val (server, port) =
                testServer(plain = true) {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "h3=\":8443\"")
                            call.respondText("plain")
                        }
                    }
                }
            try {
                val store = InMemoryAltSvcStore()
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { altSvcStore = store } }).use { c ->
                    c.get("http://127.0.0.1:$port/").bodyAsText()
                    assertTrue(store.get("http://127.0.0.1:$port").isEmpty() && store.get("https://127.0.0.1:$port").isEmpty())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 7838 section 3: an `Alt-Svc: clear` over HTTP/1.1 removes a cached alternative even while one is cached and failing. */
    @Test fun clearOverH1RemovesCachedAlternative() =
        clientTest {
            var calls = 0
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            calls++
                            call.response.header(
                                "Alt-Svc",
                                if (calls ==
                                    1
                                ) {
                                    "h3=\":${call.request.local.localPort}\""
                                } else {
                                    "clear"
                                },
                            )
                            call.respondText("h1")
                        }
                    }
                }
            try {
                val store = InMemoryAltSvcStore()
                val origin = "https://127.0.0.1:$port"
                testClient(Http3DiscoveryMode.Auto, engine = {
                    http3 { altSvcStore = store }
                    quic =
                        io.kuicksilver.quic.quicConfig { handshakeTimeout = kotlin.time.Duration.parse("500ms") }
                }).use { c ->
                    assertEquals("h1", c.get("$origin/").bodyAsText())
                    assertTrue(store.get(origin).isNotEmpty(), "the alternative was learned")
                    val second = c.get("$origin/")
                    // the UDP side answers nothing: HTTP/1.1 served it, and that response said `clear`
                    assertEquals(HttpProtocolVersion.HTTP_1_1, second.version)
                    assertTrue(store.get(origin).isEmpty(), "clear over HTTP/1.1 removed the alternative: ${store.get(origin)}")
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
