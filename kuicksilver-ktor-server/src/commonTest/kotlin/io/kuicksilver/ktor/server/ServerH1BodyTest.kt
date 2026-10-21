// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpStatusCode
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Request bodies through the engine, on real sockets: what a body that stops arriving is answered with, and what happens
 * to a body the handler does not read. The deadline itself is covered on virtual time by `h1.H1PipelineBodyTimeoutTest`.
 */
class ServerH1BodyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun plainServer(
        idleSeconds: Int = 1,
        module: Application.() -> Unit,
        block: suspend (Int) -> Unit,
    ) {
        val server =
            embeddedServer(Kuicksilver, configure = {
                connectionIdleTimeoutSeconds = idleSeconds
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
            }, module = module)
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

    /**
     * Sends [head] and then [bodySize] bytes from a coroutine of their own (a write the server refuses to take is not an
     * error here) while reading what the server sends until it closes; returns that.
     */
    private suspend fun writingClient(
        port: Int,
        head: String,
        bodySize: Int,
    ): String =
        coroutineScope {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                val socket = aSocket(selector).tcp().connect("127.0.0.1", port)
                val w = socket.openWriteChannel(autoFlush = false)
                val r = socket.openReadChannel()
                val writer =
                    launch {
                        runCatching {
                            w.writeStringUtf8(head)
                            val chunk = ByteArray(64 * 1024) { 'b'.code.toByte() }
                            var left = bodySize
                            while (left > 0) {
                                val n = minOf(left, chunk.size)
                                w.writeFully(chunk, 0, n)
                                w.flush()
                                left -= n
                            }
                        }
                    }
                val out = StringBuilder()
                val b = ByteArray(8192)
                runCatching {
                    while (true) {
                        val n = r.readAvailable(b, 0, b.size)
                        if (n < 0) break
                        out.append(b.decodeToString(0, n))
                    }
                }
                writer.cancel()
                socket.close()
                out.toString()
            } finally {
                selector.close()
            }
        }

    private val stalledPost = "POST /body HTTP/1.1\r\nHost: s\r\nContent-Length: 100\r\n\r\n0123456789"

    /** The 408 has a fixed body: the exception's message ("No byte of the request body for 1s") is not sent. */
    @Test fun negative_bodyTimeout408HasAFixedBody() =
        serverTest {
            plainServer(module = { routing { post("/body") { call.respondText(call.receiveText()) } } }) { port ->
                val r = withTimeout(10.seconds) { rawHttp(port, stalledPost, tls = null) }
                assertTrue(r.startsWith("HTTP/1.1 408 "), r)
                assertEquals("Request Timeout", r.substringAfter("\r\n\r\n"), r)
                assertTrue(r.contains("\r\nConnection: close\r\n"), r)
            }
        }

    /** An application that catches the failed read and answers 500 itself keeps its 500. */
    @Test fun applicationsOwn500AfterABodyTimeoutStays() =
        serverTest {
            plainServer(module = {
                routing {
                    post("/body") {
                        try {
                            call.receiveText()
                            call.respondText("read")
                        } catch (_: Exception) {
                            call.respondText("app", status = HttpStatusCode.InternalServerError)
                        }
                    }
                }
            }) { port ->
                val r = withTimeout(10.seconds) { rawHttp(port, stalledPost, tls = null) }
                assertTrue(r.startsWith("HTTP/1.1 500 "), r)
                assertEquals("app", r.substringAfter("\r\n\r\n"), r)
            }
        }

    /** StatusPages runs first: its answer to the failed read stays, a 500 included. */
    @Test fun statusPagesAnswerToABodyTimeoutStays() =
        serverTest {
            plainServer(module = {
                install(StatusPages) {
                    exception<Throwable> { call, _ -> call.respondText("pages", status = HttpStatusCode.InternalServerError) }
                }
                routing { post("/body") { call.respondText(call.receiveText()) } }
            }) { port ->
                val r = withTimeout(10.seconds) { rawHttp(port, stalledPost, tls = null) }
                assertTrue(r.startsWith("HTTP/1.1 500 "), r)
                assertEquals("pages", r.substringAfter("\r\n\r\n"), r)
            }
        }

    /**
     * Per request: a pipelined earlier request's own 500, answered after the later request's body timed out, stays a
     * 500. Before, a flag of the connection relabelled every 500 after a body timeout as 408.
     */
    @Test fun negative_earlierPipelinedRequestsOwn500IsNotRelabelled() =
        serverTest {
            val timedOut = CompletableDeferred<Unit>()
            plainServer(module = {
                routing {
                    get("/first") {
                        timedOut.await()
                        error("the first request fails on its own")
                    }
                    post("/body") {
                        try {
                            call.receiveText()
                        } finally {
                            timedOut.complete(Unit)
                        }
                    }
                }
            }) { port ->
                val r = withTimeout(10.seconds) { rawHttp(port, "GET /first HTTP/1.1\r\nHost: s\r\n\r\n" + stalledPost, tls = null) }
                assertTrue(r.startsWith("HTTP/1.1 500 "), r)
                assertTrue(r.contains("HTTP/1.1 408 "), r)
            }
        }

    /**
     * A body the handler does not read: one larger than 256 KiB (here 4 MiB, sent by a client that writes it all) is not
     * read to its end; the response says `Connection: close` and the connection closes after it, as Go's net/http does
     * past its 256 KiB. Before, the pipeline waited for a reader of the body that never came.
     */
    @Test fun negative_largeUnreadBodyClosesTheConnection() =
        serverTest {
            plainServer(idleSeconds = 30, module = { routing { post("/ignore") { call.respondText("ignored") } } }) { port ->
                val size = 4 * 1024 * 1024
                val r =
                    withTimeout(
                        10.seconds,
                    ) { writingClient(port, "POST /ignore HTTP/1.1\r\nHost: s\r\nContent-Length: $size\r\n\r\n", size) }
                assertTrue(r.startsWith("HTTP/1.1 200 "), r.take(200))
                assertTrue(r.contains("\r\nConnection: close\r\n"), r.take(200))
            }
        }

    /** A small body the handler does not read (10 KiB) is drained, and the next pipelined request is served. */
    @Test fun smallUnreadBodyKeepsTheConnection() =
        serverTest {
            plainServer(idleSeconds = 30, module = {
                routing {
                    post("/ignore") { call.respondText("ignored") }
                    get("/next") { call.respondText("next") }
                }
            }) { port ->
                val body = "b".repeat(10 * 1024)
                val r =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "POST /ignore HTTP/1.1\r\nHost: s\r\nContent-Length: ${body.length}\r\n\r\n$body" +
                                "GET /next HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    }
                assertTrue(r.startsWith("HTTP/1.1 200 "), r)
                assertFalse(r.substringBefore("ignored").contains("Connection: close"), r)
                assertTrue(r.endsWith("next"), r)
            }
        }

    /**
     * `Expect: 100-continue` answered without `100 Continue` (the handler did not ask for the body): the response says
     * `Connection: close` and the connection ends after it, without waiting for a body the client may never send (RFC
     * 9110 section 10.1.1; Go's net/http does the same).
     */
    @Test fun negative_expectContinueAnsweredWithoutContinueCloses() =
        serverTest {
            plainServer(idleSeconds = 30, module = {
                routing { post("/deny") { call.respondText("no", status = HttpStatusCode.Forbidden) } }
            }) { port ->
                val r =
                    withTimeout(10.seconds) {
                        rawHttp(port, "POST /deny HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n", tls = null)
                    }
                assertTrue(r.startsWith("HTTP/1.1 403 "), r)
                assertFalse(r.contains("100 Continue"), r)
                assertTrue(r.contains("\r\nConnection: close\r\n"), r)
            }
        }
}
