// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.uri
import io.ktor.server.response.ApplicationSendPipeline
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import java.util.Collections
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A WebSocket upgrade request whose route fails and whose error response fails too: the route's exception breaks the
 * error handling of the engine phase and of Ktor's fallback (its message cannot be read), and the engine's last 500 is
 * refused by an interceptor of the send pipeline, so the handler ends with an IllegalStateException before any response
 * started. The pipeline awaited the upgrade's outcome with `upgraded.await()`, which rethrew the handler's
 * failure out of the pipeline coroutine: the connection was reset, the responses queued before it were lost, and as the
 * connections' SupervisorJob had no CoroutineExceptionHandler the exception reached the thread's uncaught exception
 * handler (a process crash on Android). JVM only: the probe is the default uncaught exception handler.
 */
class UpgradeFailureJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_aFailedUpgradeWhoseErrorResponseFailsEndsOnlyItsConnection() =
        serverTest {
            val uncaught = Collections.synchronizedList(mutableListOf<Throwable>())
            val previous = Thread.getDefaultUncaughtExceptionHandler()
            Thread.setDefaultUncaughtExceptionHandler { _, e -> uncaught += e }
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) {
                    sendPipeline.intercept(ApplicationSendPipeline.Before) {
                        if (context.request.uri == "/ws") throw IllegalStateException("the error response failed too")
                    }
                    routing {
                        get("/ws") { throw UnreadableFailure(2) }
                        get("/") { call.respondText("root") }
                    }
                }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                // rawHttp reads to the end of the stream: a reset fails it
                val first =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "GET / HTTP/1.1\r\nHost: s\r\n\r\n" +
                                "GET /ws HTTP/1.1\r\nHost: s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
                                "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                            tls = null,
                        )
                    }
                assertTrue(first.startsWith("HTTP/1.1 200 ") && first.endsWith("root"), "the response queued before the upgrade: $first")
                val next = withTimeout(10.seconds) { rawHttp(port, "GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n", tls = null) }
                assertTrue(next.endsWith("root"), "the next connection: $next")
                assertEquals(emptyList(), uncaught.toList(), "uncaught exceptions")
            } finally {
                server.stop(100, 500)
                Thread.setDefaultUncaughtExceptionHandler(previous)
            }
        }

    /** A failure whose message cannot be read: reading it throws one of [depth] - 1, down to a readable one. */
    private class UnreadableFailure(
        private val depth: Int,
    ) : RuntimeException() {
        override val message: String
            get() = if (depth > 0) throw UnreadableFailure(depth - 1) else "the route failed"
    }
}
