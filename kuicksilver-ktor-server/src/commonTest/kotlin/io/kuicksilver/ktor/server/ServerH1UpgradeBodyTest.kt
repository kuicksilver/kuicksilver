// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.application.Application
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * A request that offers an upgrade (`Connection: Upgrade` with an `Upgrade` field) has no body when it carries neither
 * Content-Length nor Transfer-Encoding (RFC 9112 section 6.3 item 7), whether or not the server takes the upgrade
 * (RFC 9110 section 7.8: it MAY ignore it). The engine kept the request's body open until the response head settled
 * the upgrade, so a handler that read the body before answering waited for itself and the connection hung.
 */
class ServerH1UpgradeBodyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val routes: Application.() -> Unit = {
        routing {
            get("/text") { call.respondText("body=[" + call.receiveText() + "]") }
            get("/channel") {
                val bytes = call.receiveChannel().readBuffer().readByteArray()
                call.respondText("bytes=${bytes.size}")
            }
            get("/bytewise") {
                val channel = call.receiveChannel()
                val one = ByteArray(1)
                var n = 0
                while (channel.readAvailable(one, 0, 1) >= 0) n++
                call.respondText("bytes=$n")
            }
            get("/") { call.respondText("root") }
        }
    }

    /** The handler reads the (empty) body of an h2c upgrade offer, answers, and the next request on the connection is served. */
    @Test fun negative_aBodylessUpgradeOfferWhoseHandlerReadsTheBodyIsAnswered() =
        serverTest {
            plainServer { port ->
                val response =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "GET /text HTTP/1.1\r\nHost: s\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n" +
                                "HTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n" +
                                "GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    }
                assertEquals(listOf("body=[]", "root"), bodies(response), response)
            }
        }

    /**
     * The same for any upgrade token, the option in another case and list position, and a body read as a channel, whole
     * or in 1-byte pieces.
     */
    @Test fun negative_anyBodylessUpgradeOfferReadsAnEmptyBody() =
        serverTest {
            plainServer { port ->
                for ((path, connection, upgrade) in listOf(
                    Triple("/channel", "Upgrade", "websocket"),
                    Triple("/channel", "keep-alive, upgrade", "foo/1, bar"),
                    Triple("/bytewise", "UPGRADE", "TLS/1.2"),
                )) {
                    val response =
                        withTimeout(10.seconds) {
                            rawHttp(
                                port,
                                "GET $path HTTP/1.1\r\nHost: s\r\nConnection: $connection\r\nUpgrade: $upgrade\r\n\r\n" +
                                    "GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                                tls = null,
                            )
                        }
                    assertEquals(listOf("bytes=0", "root"), bodies(response), "$path $connection / $upgrade: $response")
                }
            }
        }

    /** The bodies of the Content-Length-framed responses in [raw], in order. */
    private fun bodies(raw: String): List<String> {
        val out = mutableListOf<String>()
        var rest = raw
        while (rest.isNotEmpty()) {
            val headEnd = rest.indexOf("\r\n\r\n")
            if (headEnd < 0) break
            val length =
                Regex("(?im)^content-length:\\s*(\\d+)")
                    .find(rest.substring(0, headEnd))
                    ?.groupValues
                    ?.get(1)
                    ?.toInt() ?: break
            out += rest.substring(headEnd + 4, headEnd + 4 + length)
            rest = rest.substring(headEnd + 4 + length)
        }
        return out
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
