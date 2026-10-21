// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The request-head size limit on a real socket; the boundaries are in `h1.H1PipelineHeadLimitTest`. */
class ServerH1HeadLimitTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * 4 MiB of header fields (1024 lines of 4 KiB, each under Ktor's 8 KiB line limit) get 431 and the connection closes;
     * before, they were buffered and the request was served (0.2.1 review). The client sends all of it before
     * reading, so the server must drain what follows the refused head for the client to see the answer.
     */
    @Test fun negative_headerSectionSizeIsBounded() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("root") } } }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val field = "X-Pad: " + "p".repeat(4000) + "\r\n"
                val resp =
                    withTimeout(20.seconds) {
                        rawHttp(port, "GET / HTTP/1.1\r\nHost: s\r\n" + field.repeat(1024) + "Connection: close\r\n\r\n", tls = null)
                    }
                assertTrue(resp.startsWith("HTTP/1.1 431 Request Header Fields Too Large\r\n"), resp.take(200))
            } finally {
                server.stop(100, 500)
            }
        }
}
