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
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
        log: CapturedLog? = null,
        module: Application.() -> Unit,
        block: suspend (Int) -> Unit,
    ) {
        val server =
            kuicksilverServer(log, configure = {
                configure()
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
     * Per request: a pipelined earlier request's own 500 stays a 500 and the later request whose body timed out gets its
     * 408. Before, a flag of the connection relabelled every 500 after a body timeout as 408. The later request is now
     * read only once the earlier response's head is out (it may say `Connection: close`, RFC 9112 section 9.6), so the
     * earlier handler can no longer wait for the later one's timeout: it fails right away.
     */
    @Test fun negative_earlierPipelinedRequestsOwn500IsNotRelabelled() =
        serverTest {
            val log = CapturedLog()
            plainServer(log = log, module = {
                routing {
                    get("/first") { error("the first request fails on its own") }
                    post("/body") { call.receiveText() }
                }
            }) { port ->
                val r = withTimeout(10.seconds) { rawHttp(port, "GET /first HTTP/1.1\r\nHost: s\r\n\r\n" + stalledPost, tls = null) }
                assertTrue(r.startsWith("HTTP/1.1 500 "), r)
                assertTrue(r.contains("HTTP/1.1 408 "), r)
                log.assertLogged("ERROR", "Unhandled: GET - /first", "the first request fails on its own")
            }
        }

    /**
     * A body the handler does not read: one larger than 256 KiB (here 32 MiB) is not read to its end; the response says
     * `Connection: close` and the connection closes after it, as Go's net/http does past its 256 KiB, and the client still
     * reads the whole response after the server has closed (`connectionClosed`). Before, the pipeline waited for a reader
     * of the body that never came. That the server drains for a while before it closes, so a client that writes its whole
     * body first is not reset, is `UnreadBodyLingerJvmTest` (a blocking socket, JVM only).
     */
    @Test fun negative_largeUnreadBodyClosesTheConnection() =
        serverTest {
            val closed = CompletableDeferred<Unit>()
            val events =
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                object : KuicksilverServerEventListener() {
                    override fun connectionClosed(
                        protocol: io.ktor.http.HttpProtocolVersion,
                        remote: io.ktor.network.sockets.InetSocketAddress?,
                    ) {
                        closed.complete(Unit)
                    }
                }
            plainServer(
                idleSeconds = 30,
                configure = {
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    eventListener = events
                },
                module = { routing { post("/ignore") { call.respondText("ignored") } } },
            ) { port ->
                val size = 32 * 1024 * 1024
                val selector = SelectorManager(Dispatchers.Default)
                try {
                    val socket = aSocket(selector).tcp().connect("127.0.0.1", port)
                    val w = socket.openWriteChannel(autoFlush = true)
                    val r = socket.openReadChannel()
                    w.writeStringUtf8("POST /ignore HTTP/1.1\r\nHost: s\r\nContent-Length: $size\r\n\r\n")
                    w.writeFully(ByteArray(size) { 'b'.code.toByte() })
                    w.flush()
                    withTimeout(15.seconds) { closed.await() }
                    val out = StringBuilder()
                    val b = ByteArray(8192)
                    withTimeout(10.seconds) {
                        while (true) {
                            val n = r.readAvailable(b, 0, b.size)
                            if (n < 0) break
                            out.append(b.decodeToString(0, n))
                        }
                    }
                    val text = out.toString()
                    assertTrue(text.startsWith("HTTP/1.1 200 "), text.take(200))
                    assertTrue(text.contains("\r\nConnection: close\r\n"), text.take(200))
                    assertTrue(text.endsWith("\r\n\r\nignored"), text.take(300))
                    socket.close()
                } finally {
                    selector.close()
                }
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

    /** A body of exactly 256 KiB the handler does not read is drained in full: the cap is inclusive. */
    @Test fun unreadBodyOfExactlyTheCapKeepsTheConnection() =
        serverTest {
            plainServer(idleSeconds = 30, module = {
                routing {
                    post("/ignore") { call.respondText("ignored") }
                    get("/next") { call.respondText("next") }
                }
            }) { port ->
                val body = "b".repeat(256 * 1024)
                val r =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "POST /ignore HTTP/1.1\r\nHost: s\r\nContent-Length: ${body.length}\r\n\r\n$body" +
                                "GET /next HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    }
                assertFalse(r.substringBefore("ignored").contains("Connection: close"), r)
                assertTrue(r.endsWith("next"), r)
            }
        }

    /**
     * A chunked body the handler has not read by its response (here 4 MiB, more than the channel to the handler holds,
     * so it cannot be complete then) is of unknown size: the response head says `Connection: close`, and the connection
     * ends after it, so a request pipelined after the body is not attempted. Before, the head promised keep-alive and the
     * connection closed after all once the drain passed 256 KiB.
     */
    @Test fun negative_unreadChunkedBodyClosesTheConnectionAsItsHeadSays() =
        serverTest {
            plainServer(idleSeconds = 30, module = {
                routing {
                    post("/ignore") { call.respondText("no", status = HttpStatusCode.Unauthorized) }
                    get("/next") { call.respondText("next") }
                }
            }) { port ->
                val chunk = "c".repeat(64 * 1024)
                val chunked = "10000\r\n$chunk\r\n".repeat(64) + "0\r\n\r\n"
                val r =
                    withTimeout(10.seconds) {
                        rawHttp(
                            port,
                            "POST /ignore HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n$chunked" +
                                "GET /next HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n",
                            tls = null,
                        )
                    }
                assertTrue(r.startsWith("HTTP/1.1 401 "), r.take(200))
                assertTrue(r.contains("\r\nConnection: close\r\n"), r.take(200))
                assertFalse(r.contains("next"), "the pipelined request after the body was served: ${r.take(300)}")
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
