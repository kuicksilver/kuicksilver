// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.server.websocket.WebSocketUpgrade
import io.ktor.server.websocket.WebSockets
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.CoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The 101 an application sends on HTTP/1.1 (RFC 9110 section 7.8): it MUST name the new protocol in Upgrade and MUST
 * NOT switch to one the request did not offer, so an upgrade that breaks either goes out as 500 and the connection stays
 * HTTP/1.1. The WebSocket checks (RFC 6455 section 4.2.1 refusals, the frame guard) apply when the 101 switches to
 * `websocket`, whichever Upgrade field line of the request offered it.
 */
class ServerH1UpgradeResponseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val routes: Application.() -> Unit = {
        install(WebSockets)
        routing {
            // switches to the protocols of `?p=` (none: no Upgrade field), then writes "switched" and ends
            get("/up") {
                val protocol = call.request.queryParameters["p"]
                call.respond(
                    object : OutgoingContent.ProtocolUpgrade() {
                        override val headers: Headers =
                            if (protocol == null) {
                                headersOf(HttpHeaders.Connection, "Upgrade")
                            } else {
                                headersOf(HttpHeaders.Upgrade to listOf(protocol), HttpHeaders.Connection to listOf("Upgrade"))
                            }

                        override suspend fun upgrade(
                            input: ByteReadChannel,
                            output: ByteWriteChannel,
                            engineContext: CoroutineContext,
                            userContext: CoroutineContext,
                        ): Job =
                            CoroutineScope(engineContext).launch {
                                output.writeStringUtf8("switched")
                                output.flushAndClose()
                            }
                    },
                )
            }
            // a WebSocket upgrade without Ktor's header selectors (its routing reads only the first Upgrade line)
            get("/ws") { call.respond(WebSocketUpgrade(call) { }) }
            get("/") { call.respondText("root") }
        }
    }

    /** A 101 that names no protocol, or one the request did not offer, goes out as 500 and the next request is served. */
    @Test fun negative_anUpgradeTheRequestDidNotOfferIsA500() =
        serverTest {
            plainServer { port ->
                for ((query, offer) in listOf(
                    "" to "h2c",
                    "?p=foo" to "h2c",
                    "?p=h2c,%20foo" to "h2c",
                    "?p=foo/2" to "foo/1",
                    "?p=%20,%20" to "foo",
                )) {
                    val response =
                        withTimeout(10.seconds) {
                            rawHttp(
                                port,
                                "GET /up$query HTTP/1.1\r\nHost: s\r\nConnection: Upgrade\r\nUpgrade: $offer\r\n\r\n" +
                                    "GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                                tls = null,
                            )
                        }
                    assertTrue(response.startsWith("HTTP/1.1 500 "), "$query / $offer: $response")
                    assertFalse(" 101 " in response || "switched" in response, "$query / $offer: $response")
                    assertTrue(response.endsWith("root"), "$query / $offer: $response")
                }
            }
        }

    /** A 101 to a protocol the request offered, in another case, on another field line, or without the offered version. */
    @Test fun anOfferedUpgradeSwitches() =
        serverTest {
            plainServer { port ->
                for ((query, upgradeLines) in listOf(
                    "?p=FOO" to "Upgrade: foo\r\n",
                    "?p=foo" to "Upgrade: h2c\r\nUpgrade: foo/1\r\n",
                    "?p=foo/1" to "Upgrade: bar, Foo/1\r\n",
                )) {
                    val response =
                        withTimeout(10.seconds) {
                            rawHttp(port, "GET /up$query HTTP/1.1\r\nHost: s\r\nConnection: Upgrade\r\n$upgradeLines\r\n", tls = null)
                        }
                    assertTrue(response.startsWith("HTTP/1.1 101 ") && response.endsWith("switched"), "$query: $response")
                }
            }
        }

    /**
     * A WebSocket offered on the request's second Upgrade line still gets the RFC 6455 handshake checks: a version other
     * than 13 is answered 426, not switched. Before, only the first line was looked at, and the handshake went through
     * unchecked. (Ktor's `webSocket` route reads only the first line and answers 400 itself; an application that responds
     * with `WebSocketUpgrade` directly reaches the engine.)
     */
    @Test fun negative_aWebSocketOfferOnASecondUpgradeLineIsChecked() =
        serverTest {
            plainServer { port ->
                val response =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "GET /ws HTTP/1.1\r\nHost: s\r\nConnection: Upgrade, close\r\nUpgrade: h2c\r\nUpgrade: websocket\r\n" +
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
                            tls = null,
                        )
                    }
                assertTrue(response.startsWith("HTTP/1.1 426 "), response)
            }
        }

    private suspend fun plainServer(block: suspend (Int) -> Unit) {
        val server =
            embeddedServer(Kuicksilver, configure = {
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
            }, module = routes)
        server.startSuspend(false)
        try {
            block(
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port,
            )
        } finally {
            server.stop(100, 500)
        }
    }
}
