// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.HttpMethod
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.content.OutgoingContent
import io.ktor.network.selector.SelectorManager
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import io.kuicksilver.ktor.client.KuicksilverEventListener
import io.kuicksilver.quic.KuicksilverLogger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Whether an idle pooled HTTP/1.1 connection may carry the next request. */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class H1IdleConnectionTest {
    /** An idle connection of the pool on [wire], route "r". */
    private suspend fun idle(wire: Wire): Pair<ConnectionPool<H1Connection>, H1Connection> {
        val pool = ConnectionPool<H1Connection>(KuicksilverEngineConfig().poolLimits()) { 0L }
        assertNull(pool.acquire("r"))
        val conn = H1Connection(NoSocket(wire), null, wire.fromServer, wire.toServer, "r")
        pool.adopt(conn)
        assertTrue(pool.release(conn))
        return pool to conn
    }

    /**
     * A server that answers nothing in particular on an idle keep-alive connection (`408 Request Timeout` and a close, RFC
     * 9110 section 15.5.9) leaves bytes no request asked for: the connection is not reused, and the next request gets a
     * fresh one (RFC 9112 section 9.2: the client MUST NOT consider such data a valid response, and SHOULD close the
     * connection). Before, the 408 was read as the answer to that request.
     */
    @Test fun unsolicitedResponseOnIdleConnectionIsNotReused() =
        runTest {
            val wire = Wire()
            val (pool, conn) = idle(wire)
            wire.fromServer.writeStringUtf8("HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
            wire.fromServer.flushAndClose()
            assertNull(pool.acquire("r"), "the connection with the stale 408 was handed out")
            assertTrue(conn.closed)
        }

    /** Unsolicited bytes on a connection the server keeps open make it unusable as well. */
    @Test fun strayBytesOnIdleConnectionAreNotReused() =
        runTest {
            val wire = Wire()
            val (pool, conn) = idle(wire)
            wire.fromServer.writeStringUtf8("x")
            wire.fromServer.flush()
            assertNull(pool.acquire("r"))
            assertTrue(conn.closed)
        }

    /** An idle connection with nothing to read is reused. */
    @Test fun quietIdleConnectionIsReused() =
        runTest {
            val wire = Wire()
            val (pool, conn) = idle(wire)
            assertSame(conn, pool.acquire("r"))
            assertEquals(false, conn.closed)
        }

    /**
     * The connection of a response whose body was read to its end is back in the pool when the application sees that end,
     * so the next request on the route takes it. Before, the body's channel was closed first and the connection released
     * after, when the body reader's coroutine completed: an application that resumed at once (another thread, or inline as
     * here) could send its next request in between, which found no idle connection and opened another one (a hang of
     * `ClientH1Test.continueResponseIsSkipped` on a slow Android 7.0 emulator, whose server answers one connection only).
     */
    @Test fun connectionIsIdleWhenTheBodyEnds() =
        runTest {
            val wire = Wire()
            val selector = SelectorManager(Dispatchers.Default)
            val h1 = H1Pool(KuicksilverEngineConfig(), selector)
            h1.cleartextPermitted = { true }
            assertNull(h1.pool.acquire("r"))
            val conn = H1Connection(NoSocket(wire), null, wire.fromServer, wire.toServer, "r").also { h1.pool.adopt(it) }
            val call = Job()
            try {
                backgroundScope.launch {
                    while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                    wire.fromServer.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
                    wire.fromServer.flush()
                }
                val data = HttpRequestBuilder().apply { url("http://127.0.0.1:8080/") }.build()
                val response = h1.execute(data, coroutineContext + call, H1Pool.Opened(conn, reused = false))
                val body = response.body as ByteReadChannel
                // the application waits for the body in a coroutine that resumes inline, in the body reader's coroutine,
                // as soon as the body ends: what it sees then is what a request it sends next finds
                val seen = CompletableDeferred<Pair<String, Int>>()
                launch(Dispatchers.Unconfined) { seen.complete(body.readBuffer().readString() to h1.pool.idleCount) }
                wire.fromServer.writeStringUtf8("first")
                wire.fromServer.flush()
                assertEquals("first" to 1, seen.await(), "the body ended before its connection was idle")
                assertSame(conn, h1.pool.acquire("r"))
            } finally {
                call.cancel()
                selector.close()
            }
        }

    /** A request body of [length] bytes the test streams through [source]. */
    private class Upload(
        private val source: ByteReadChannel,
        private val length: Long = 3,
    ) : OutgoingContent.ReadChannelContent() {
        override val contentLength: Long get() = length

        override fun readFrom(): ByteReadChannel = source
    }

    /** A pool with one connection on [wire], route "r", handed to [execute]; [released] lists connectionReleased's `kept`. */
    private class Pooled(
        val wire: Wire,
        val selector: SelectorManager,
    ) {
        val released = mutableListOf<Boolean>()

        /** The first connectionReleased's `kept`. */
        val firstRelease = CompletableDeferred<Boolean>()
        val h1 =
            H1Pool(
                KuicksilverEngineConfig(),
                selector,
                EngineEvents(
                    object : KuicksilverEventListener() {
                        override fun connectionReleased(
                            request: HttpRequestData,
                            protocol: HttpProtocolVersion,
                            kept: Boolean,
                        ) {
                            released += kept
                            firstRelease.complete(kept)
                        }
                    },
                    KuicksilverLogger.None,
                ),
            ).also { it.cleartextPermitted = { true } }
        val conn = H1Connection(NoSocket(wire), null, wire.fromServer, wire.toServer, "r")
        val call = Job()

        suspend fun execute(
            data: HttpRequestData,
            context: kotlin.coroutines.CoroutineContext,
        ): io.ktor.client.request.HttpResponseData {
            assertNull(h1.pool.acquire("r"))
            h1.pool.adopt(conn)
            return h1.execute(data, context + call, H1Pool.Opened(conn, reused = false))
        }
    }

    private fun TestScope.pooled(block: suspend Pooled.() -> Unit) =
        launch {
            val selector = SelectorManager(Dispatchers.Default) // H1Pool wants one; nothing here selects on it
            val p = Pooled(Wire(), selector)
            try {
                p.block()
            } finally {
                p.call.cancel()
                selector.close()
            }
        }

    private fun request(
        body: OutgoingContent? = null,
        method: HttpMethod = if (body == null) HttpMethod.Get else HttpMethod.Post,
    ): HttpRequestData =
        HttpRequestBuilder()
            .apply {
                url("http://127.0.0.1:8080/upload")
                this.method = method
                body?.let { setBody(it) }
            }.build()

    /** The server: reads a request head, writes [answer], then reads [bodyBytes] of the request body into [received]. */
    private fun TestScope.server(
        wire: Wire,
        answer: String,
        bodyBytes: Int = 3,
        received: CompletableDeferred<String> = CompletableDeferred(),
    ): CompletableDeferred<String> {
        backgroundScope.launch {
            while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
            wire.fromServer.writeStringUtf8(answer)
            wire.fromServer.flush()
            runCatching { received.complete(wire.toServer.readByteArray(bodyBytes).decodeToString()) } // fails with a failed body
        }
        return received
    }

    private val ok = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

    /**
     * A streamed request body still being sent when the server has answered in full: the response ends at once, without
     * waiting for the upload, and its connection is not reused (never pooled); the upload is not cut off, and the
     * connection closes when it is out. Before, the response ended only once the upload was out.
     */
    @Test fun aResponseThatEndsWhileTheRequestBodyIsSentIsNotReused() =
        runTest {
            pooled {
                val upload = ByteChannel()
                val received = server(wire, ok)
                val response = execute(request(Upload(upload)), coroutineContext)
                assertEquals("ok", (response.body as ByteReadChannel).readBuffer().readString())
                assertEquals(0, h1.pool.idleCount, "a connection whose request body is still being sent was pooled")
                assertFalse(conn.closed, "the upload was cut off")
                upload.writeStringUtf8("abc")
                upload.flushAndClose()
                assertEquals("abc", received.await())
                assertEquals(false, firstRelease.await())
                assertTrue(conn.closed)
                assertEquals(listOf(false), released)
                assertNull(h1.pool.acquire("r"), "a permit, not the connection")
            }
        }

    /** Duplex: the application sends part of its body, reads the whole response, then ends its body. The call completes. */
    @Test fun aDuplexExchangeCompletes() =
        runTest {
            pooled {
                val upload = ByteChannel()
                val received = server(wire, ok)
                upload.writeStringUtf8("a")
                upload.flush()
                val response = execute(request(Upload(upload)), coroutineContext)
                assertEquals("ok", (response.body as ByteReadChannel).readBuffer().readString())
                upload.writeStringUtf8("bc")
                upload.flushAndClose()
                assertEquals("abc", received.await())
                assertEquals(false, firstRelease.await())
                assertTrue(conn.closed)
                assertEquals(listOf(false), released)
            }
        }

    /**
     * An early `413 Content Too Large` without `Connection: close` from a server that stopped reading (RFC 9112 section 9.5:
     * it should cease reading and close): the call completes with the 413 while the upload is stuck, and the connection
     * closes when the call ends.
     */
    @Test fun anEarly413FromAServerThatStoppedReadingCompletes() =
        runTest {
            pooled {
                val size = 4L * 1024 * 1024 // more than the in-memory wire buffers: the upload blocks
                val upload = ByteChannel()
                backgroundScope.launch { runCatching { upload.writeFully(ByteArray(size.toInt())) } }
                backgroundScope.launch {
                    while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                    wire.fromServer.writeStringUtf8("HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
                    wire.fromServer.flush()
                }
                val response = execute(request(Upload(upload, size)), coroutineContext)
                assertEquals(413, response.statusCode.value)
                assertEquals(0, (response.body as ByteReadChannel).readBuffer().size)
                assertEquals(0, h1.pool.idleCount)
                call.cancel() // the call ends
                assertEquals(false, firstRelease.await())
                assertTrue(conn.closed)
                assertEquals(listOf(false), released)
                assertEquals(0, h1.pool.liveCount)
            }
        }

    /** A 204 (no body, as HEAD and 304) to a request without a body, or whose streamed body is out, goes back to the pool at once. */
    @Test fun aResponseWithoutBodyIsReused() =
        runTest {
            for (streamed in listOf(false, true)) {
                pooled {
                    val upload = ByteChannel()
                    val received = CompletableDeferred<String>()
                    backgroundScope.launch {
                        while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                        if (streamed) received.complete(wire.toServer.readByteArray(3).decodeToString())
                        wire.fromServer.writeStringUtf8("HTTP/1.1 204 No Content\r\n\r\n")
                        wire.fromServer.flush()
                    }
                    if (streamed) {
                        upload.writeStringUtf8("abc")
                        upload.flushAndClose()
                    }
                    val response = execute(if (streamed) request(Upload(upload)) else request(), coroutineContext)
                    assertEquals(204, response.statusCode.value)
                    assertEquals(1, h1.pool.idleCount, "streamed=$streamed")
                    assertEquals(listOf(true), released)
                    assertSame(conn, h1.pool.acquire("r"))
                    if (streamed) assertEquals("abc", received.await())
                }
            }
        }

    /** The call ending after its streamed body went out (the sender is cancelled with it) leaves the pooled connection open. */
    @Test fun aCallEndingAfterItsBodyWentOutKeepsThePooledConnection() =
        runTest {
            pooled {
                val upload = ByteChannel()
                upload.writeStringUtf8("abc")
                upload.flushAndClose()
                backgroundScope.launch {
                    while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                    wire.toServer.readByteArray(3)
                    wire.fromServer.writeStringUtf8(ok)
                    wire.fromServer.flush()
                }
                val response = execute(request(Upload(upload)), coroutineContext)
                assertEquals("ok", (response.body as ByteReadChannel).readBuffer().readString())
                assertEquals(1, h1.pool.idleCount)
                call.cancel()
                assertFalse(conn.closed)
                assertSame(conn, h1.pool.acquire("r"))
            }
        }

    /** A call that ends while its connection waits for the upload to end closes the connection, once, and frees its slot. */
    @Test fun aCallEndingDuringTheUploadClosesTheConnection() =
        runTest {
            pooled {
                val upload = ByteChannel()
                server(wire, ok)
                val response = execute(request(Upload(upload)), coroutineContext)
                assertEquals("ok", (response.body as ByteReadChannel).readBuffer().readString())
                assertFalse(conn.closed)
                call.cancel()
                assertEquals(false, firstRelease.await())
                assertTrue(conn.closed)
                assertEquals(listOf(false), released)
                assertEquals(0, h1.pool.liveCount)
            }
        }

    /** A streamed request body that fails (the application's channel) leaves its connection closed; the response still ends. */
    @Test fun negative_aFailedStreamedRequestBodyClosesTheConnection() =
        runTest {
            pooled {
                val upload = ByteChannel()
                server(wire, ok)
                val response = execute(request(Upload(upload)), coroutineContext)
                assertEquals("ok", (response.body as ByteReadChannel).readBuffer().readString())
                upload.writeStringUtf8("a")
                upload.flush()
                upload.cancel(IOException("the application's body failed"))
                assertEquals(false, firstRelease.await())
                assertTrue(conn.closed)
                assertEquals(listOf(false), released)
                assertEquals(0, h1.pool.idleCount)
            }
        }
}
