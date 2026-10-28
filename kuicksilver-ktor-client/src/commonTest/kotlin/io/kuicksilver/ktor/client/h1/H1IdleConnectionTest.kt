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
import kotlinx.coroutines.test.advanceUntilIdle
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
     * fresh one. Before, the 408 was read as the answer to that request (Go's net/http drops such a connection too).
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

    /** A request body of three bytes the test streams through [source]. */
    private class Upload(
        private val source: ByteReadChannel,
    ) : OutgoingContent.ReadChannelContent() {
        override val contentLength: Long get() = 3

        override fun readFrom(): ByteReadChannel = source
    }

    /**
     * A POST whose streamed body ([upload]) is still being sent when the server has answered it in full, on a pooled
     * connection of route "r": the response's body as an application reading it in an Unconfined coroutine sees it end,
     * with the idle connections and the uploaded bytes still unsent at that moment ([observe] gets them), after [finish]
     * ended the upload.
     */
    private fun TestScope.earlyAnswer(
        finish: suspend (upload: ByteChannel) -> Unit,
        observe: (body: String, idle: Int, conn: H1Connection, unsent: Boolean) -> Unit,
    ) {
        val wire = Wire()
        val selector = SelectorManager(Dispatchers.Default)
        val upload = ByteChannel()
        var releasedWithUnsentBody: Boolean? = null
        val events =
            EngineEvents(
                object : KuicksilverEventListener() {
                    override fun connectionReleased(
                        request: HttpRequestData,
                        protocol: HttpProtocolVersion,
                        kept: Boolean,
                    ) {
                        if (kept) releasedWithUnsentBody = !upload.isClosedForRead
                    }
                },
                KuicksilverLogger.None,
            )
        val h1 = H1Pool(KuicksilverEngineConfig(), selector, events)
        h1.cleartextPermitted = { true }
        val call = Job()
        backgroundScope.launch {
            while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
            // the whole answer before the request body, as a server may send it
            wire.fromServer.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            wire.fromServer.flush()
            runCatching { wire.toServer.readByteArray(3) } // the body, which fails in the negative test
        }
        launch {
            try {
                assertNull(h1.pool.acquire("r"))
                val conn = H1Connection(NoSocket(wire), null, wire.fromServer, wire.toServer, "r").also { h1.pool.adopt(it) }
                val data =
                    HttpRequestBuilder()
                        .apply {
                            url("http://127.0.0.1:8080/upload")
                            method = HttpMethod.Post
                            setBody(Upload(upload))
                        }.build()
                val response = h1.execute(data, coroutineContext + call, H1Pool.Opened(conn, reused = false))
                val body = response.body as ByteReadChannel
                val seen = CompletableDeferred<Unit>()
                launch(Dispatchers.Unconfined) {
                    val text = body.readBuffer().readString()
                    observe(text, h1.pool.idleCount, conn, !upload.isClosedForRead)
                    seen.complete(Unit)
                }
                advanceUntilIdle()
                finish(upload)
                seen.await()
                assertEquals(false, releasedWithUnsentBody ?: false, "the connection went back before the request body was out")
            } finally {
                call.cancel()
                selector.close()
            }
        }
    }

    /**
     * A streamed request body still being sent when the response has been read: the connection goes back once the body is
     * out, and before the response's end reaches the application, which therefore sees its end only then. Before, the
     * response ended at once and the connection was released when the body's sender completed, after the application had
     * seen both ends: a request it sent then found no idle connection.
     */
    @Test fun connectionIsIdleWhenTheBodyEndsAfterAStreamedRequestBody() =
        runTest {
            var ended = false
            earlyAnswer(
                finish = { upload ->
                    assertFalse(ended, "the response ended while the request body was still being sent")
                    upload.writeStringUtf8("abc")
                    upload.flushAndClose()
                },
                observe = { body, idle, conn, unsent ->
                    ended = true
                    assertEquals("ok", body)
                    assertEquals(false, unsent, "the response ended before the request body was out")
                    assertEquals(1, idle, "the response ended before its connection was idle")
                    assertFalse(conn.closed)
                },
            )
        }

    /** A streamed request body that fails (the application's channel) leaves its connection closed; the response still ends. */
    @Test fun negative_aFailedStreamedRequestBodyClosesTheConnection() =
        runTest {
            earlyAnswer(
                finish = { upload ->
                    upload.writeStringUtf8("a")
                    upload.flush()
                    upload.cancel(IOException("the application's body failed"))
                },
                observe = { body, idle, conn, _ ->
                    assertEquals("ok", body)
                    assertEquals(0, idle)
                    assertTrue(conn.closed)
                },
            )
        }
}
