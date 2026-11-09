// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.call
import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.connector
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.head
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.Source
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A response whose content is a channel that failed (`call.respond(channel)`, a proxy relaying an upstream body that was
 * cut) is cut short, never ended as complete. Ktor's `respondFromChannel` copies with ktor-io's `copyTo`, which stops on a
 * channel failed with a cause as on one that ended, without throwing, when the failure was there before its read (it
 * throws only when it was waiting for content at that moment); the engine then ended the response cleanly: the last
 * chunk on HTTP/1.1 (RFC 9112 section 7.1), a FIN after a close-delimited body (section 8), a FIN on HTTP/3 (RFC 9114
 * section 4.1), so the client took the cut body for the whole one. An abandoned HTTP/3 response is reset with
 * H3_REQUEST_CANCELLED (RFC 9114 section 4.1.1).
 */
class ServerFailedChannelResponseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Opened by the client once it has read "hello": the content fails only then, so "hello" is on the wire before. */
    private val gate = CompletableDeferred<Unit>()

    /**
     * "hello", then, once [gate] (when given) is open, a failure with [cause] that lands right after the reader's wait for
     * more content returned, before it looks at the channel again: the case where ktor-io's `copyTo` and `discard` stop as
     * at an end. Failed, it is as ktor-io's `ByteChannel` has it: "closed for read", `readBuffer` throws.
     */
    @OptIn(InternalAPI::class)
    private class HelloThenFails(
        private val cause: Throwable,
        private val gate: CompletableDeferred<Unit>?,
    ) : ByteReadChannel {
        private val buffer = Buffer().apply { write("hello".encodeToByteArray()) }

        @Volatile private var landing = false

        @Volatile private var failed = false

        private fun land() {
            if (landing) failed = true
        }

        override val closedCause: Throwable? get() {
            land()
            return if (failed) cause else null
        }
        override val isClosedForRead: Boolean get() {
            land()
            return failed
        }
        override val readBuffer: Source get() {
            if (failed) throw cause
            return buffer
        }

        override suspend fun awaitContent(min: Int): Boolean {
            if (failed) throw cause
            if (buffer.size >= min) return true
            gate?.await()
            landing = true
            return false
        }

        override fun cancel(cause: Throwable?) {}
    }

    /** Some content, then a failure recorded before anything reads it. */
    private suspend fun failedChannel(): ByteReadChannel {
        val ch = ByteChannel()
        ch.writeStringUtf8("the start of the content")
        ch.flush()
        ch.cancel(IOException("the upstream body was cut"))
        return ch
    }

    private fun lengthThenFails(status: HttpStatusCode = HttpStatusCode.OK) =
        object : OutgoingContent.ReadChannelContent() {
            override val contentLength = 5L
            override val status = status

            override fun readFrom(): ByteReadChannel = HelloThenFails(IOException("failed after its whole content"), null)
        }

    /** A server with a plain and a TLS connector (HTTP/3 on its port); [block] gets both ports. */
    private suspend fun withServer(block: suspend (plain: Int, tls: Int) -> Unit) {
        val server =
            kuicksilverServer(null, configure = {
                connector {
                    host = "127.0.0.1"
                    port = 0
                }
                tlsConnector(ServerFixtures.identity()) {
                    host = "127.0.0.1"
                    port = 0
                }
            }) {
                routing {
                    get("/failed") { call.respond(failedChannel()) }
                    get("/io") { call.respond(HelloThenFails(IOException("the upstream body was cut"), gate)) }
                    get("/cancelled") { call.respond(HelloThenFails(CancellationException("the upstream call was cancelled"), gate)) }
                    get("/length") { call.respond(lengthThenFails()) }
                    head("/head-failed") { call.respond(failedChannel()) }
                    get("/204-failed") {
                        call.respond(
                            object : OutgoingContent.ReadChannelContent() {
                                override val status = HttpStatusCode.NoContent

                                override fun readFrom(): ByteReadChannel = HelloThenFails(IOException("never read"), null)
                            },
                        )
                    }
                }
            }
        server.startSuspend(false)
        try {
            val connectors = server.engine.resolvedConnectors()
            block(connectors.first { it.type == ConnectorType.HTTP }.port, connectors.first { it.type == ConnectorType.HTTPS }.port)
        } finally {
            server.stop(100, 500)
        }
    }

    /**
     * Sends [request] over plain TCP and reads to the end: what arrived, and whether the connection failed (a reset)
     * rather than ended. Once "hello" arrived it opens [gate] and sends [next], if any, on the same connection.
     */
    private suspend fun h1(
        port: Int,
        request: String,
        next: String? = null,
    ): Pair<String, Boolean> {
        val selector = SelectorManager(Dispatchers.IO)
        try {
            val socket = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
            try {
                val w = socket.openWriteChannel(autoFlush = true)
                val r = socket.openReadChannel()
                w.writeStringUtf8(request)
                w.flush()
                val out = StringBuilder()
                val b = ByteArray(8192)
                val failed =
                    try {
                        withTimeout(10.seconds) {
                            while (true) {
                                val n = r.readAvailable(b, 0, b.size)
                                if (n < 0) break
                                out.append(b.decodeToString(0, n))
                                if (!gate.isCompleted && "hello" in out) {
                                    gate.complete(Unit)
                                    if (next != null) runCatching { w.writeStringUtf8(next) }
                                }
                            }
                        }
                        r.closedCause != null
                    } catch (e: IOException) {
                        true
                    }
                return out.toString() to failed
            } finally {
                socket.close()
            }
        } finally {
            selector.close()
        }
    }

    private suspend fun <T> h3(
        port: Int,
        block: suspend (Http3Connection) -> T,
    ): T {
        val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
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

    /** The HTTP/3 reset code behind [e], or null when it is not a stream reset. */
    private fun resetCode(e: Throwable?): Long? =
        generateSequence(e) { it.cause }.firstNotNullOfOrNull {
            when (it) {
                is Http3Exception.Protocol -> it.h3Code
                is QuicException.StreamError.Reset -> it.code
                else -> null
            }
        }

    /** Reads [path] over HTTP/3, opening [gate] once "hello" arrived: the bytes read and the failure, if any. */
    private suspend fun h3Get(
        c: Http3Connection,
        path: String,
        method: String = "GET",
    ): Pair<String, Throwable?> {
        val out = StringBuilder()
        val failure =
            runCatching {
                withTimeout(10.seconds) {
                    val r = c.request(http3Request(method, "server.test", path))
                    val b = ByteArray(8192)
                    while (true) {
                        val n = r.body.readAvailable(b, 0, b.size)
                        if (n < 0) break
                        out.append(b.decodeToString(0, n))
                        if ("hello" in out) gate.complete(Unit)
                    }
                    r.body.closedCause?.let { throw it }
                }
            }.exceptionOrNull()
        return out.toString() to failure
    }

    private fun assertCutChunked(
        resp: String,
        failed: Boolean,
    ) {
        assertTrue(resp.startsWith("HTTP/1.1 200 "), resp)
        assertTrue(resp.contains("\r\nTransfer-Encoding: chunked\r\n"), resp)
        assertTrue(resp.contains("\r\n5\r\nhello\r\n"), "the content before the failure went out: $resp")
        assertFalse(resp.contains("\r\n0\r\n\r\n"), "a failed body ended with the last chunk: $resp")
        assertTrue(failed, "the connection ended cleanly after a failed body: $resp")
    }

    /** RFC 9112 section 7.1: the last chunk ends a chunked body; a body that failed must not get one. */
    @Test fun negative_aFailedContentChannelGetsNoLastChunkOverHttp11() =
        serverTest {
            withServer { plain, _ ->
                val (resp, failed) = h1(plain, "GET /io HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
                assertCutChunked(resp, failed)
            }
        }

    /** The same on a kept-alive connection: the next request gets no response after the cut one, the connection fails. */
    @Test fun negative_aFailedContentChannelEndsAKeptAliveConnection() =
        serverTest {
            withServer { plain, _ ->
                val (resp, failed) = h1(plain, "GET /io HTTP/1.1\r\nHost: s\r\n\r\n", next = "GET /length HTTP/1.1\r\nHost: s\r\n\r\n")
                assertCutChunked(resp, failed)
                assertEquals(1, Regex("HTTP/1\\.1 ").findAll(resp).count(), "a response followed the cut one: $resp")
            }
        }

    /**
     * An HTTP/1.0 response without Content-Length is delimited by the close (RFC 9112 section 6.3 item 8): a FIN after a
     * failed body would end it as complete (section 8), so the connection is reset. A channel cancelled with a
     * CancellationException passed as the connection's own cancellation, which ends with a FIN.
     */
    @Test fun negative_aCancelledContentChannelResetsACloseDelimitedResponse() =
        serverTest {
            withServer { plain, _ ->
                val (resp, failed) = h1(plain, "GET /cancelled HTTP/1.0\r\nHost: s\r\n\r\n")
                assertTrue(resp.startsWith("HTTP/1.0 200 ") || resp.startsWith("HTTP/1.1 200 "), resp)
                assertFalse(resp.contains("Content-Length", ignoreCase = true), resp)
                assertTrue(resp.endsWith("hello"), resp)
                assertTrue(failed, "a close-delimited body that failed ended with a FIN: $resp")
            }
        }

    /** A channel that fails after all its Content-Length bytes went out leaves a complete response: no reset. */
    @Test fun aFailureAfterTheWholeContentLengthKeepsTheResponseOverHttp11() =
        serverTest {
            withServer { plain, _ ->
                val (resp, failed) = h1(plain, "GET /length HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n")
                assertTrue(resp.startsWith("HTTP/1.1 200 "), resp)
                assertTrue(resp.contains("\r\nContent-Length: 5\r\n"), resp)
                assertTrue(resp.endsWith("\r\n\r\nhello"), resp)
                assertFalse(failed, "a complete response was cut: $resp")
            }
        }

    /** RFC 9114 sections 4.1 and 4.1.1: a channel that failed before the copy read it resets the stream, H3_REQUEST_CANCELLED. */
    @Test fun negative_aFailedContentChannelIsNotEndedOverHttp3() =
        h3ServerTest {
            withServer { _, tls ->
                h3(tls) { c ->
                    val (_, failure) = h3Get(c, "/failed")
                    assertEquals(Http3ErrorCode.REQUEST_CANCELLED, resetCode(failure), "a failed body ended with a FIN: $failure")
                }
            }
        }

    /** The same after part of the content went out. */
    @Test fun negative_aContentChannelFailingMidBodyResetsTheStreamOverHttp3() =
        h3ServerTest {
            withServer { _, tls ->
                h3(tls) { c ->
                    val (body, failure) = h3Get(c, "/io")
                    assertEquals("hello", body)
                    assertEquals(Http3ErrorCode.REQUEST_CANCELLED, resetCode(failure), "$failure")
                }
            }
        }

    /** A channel cancelled with a CancellationException left the stream with neither a FIN nor a reset. */
    @Test fun negative_aCancelledContentChannelResetsTheStreamOverHttp3() =
        h3ServerTest {
            withServer { _, tls ->
                h3(tls) { c ->
                    val (body, failure) = h3Get(c, "/cancelled")
                    assertEquals("hello", body)
                    assertEquals(Http3ErrorCode.REQUEST_CANCELLED, resetCode(failure), "$failure")
                }
            }
        }

    /** A channel that fails after all its Content-Length bytes leaves a complete HTTP/3 response. */
    @Test fun aFailureAfterTheWholeContentLengthKeepsTheResponseOverHttp3() =
        h3ServerTest {
            withServer { _, tls ->
                h3(tls) { c ->
                    val (body, failure) = h3Get(c, "/length")
                    assertEquals(null, failure)
                    assertEquals("hello", body)
                }
            }
        }

    /** HEAD and 204 have no content (RFC 9110 sections 9.3.2, 15.3.5): the channel is not read, its failure resets nothing. */
    @Test fun aResponseWithoutContentDoesNotReadItsFailedChannelOverHttp3() =
        h3ServerTest {
            withServer { _, tls ->
                h3(tls) { c ->
                    for ((method, path) in listOf("HEAD" to "/head-failed", "GET" to "/204-failed")) {
                        val (body, failure) = h3Get(c, path, method)
                        assertEquals(null, failure, "$method $path")
                        assertEquals("", body, "$method $path")
                    }
                }
            }
        }
}
