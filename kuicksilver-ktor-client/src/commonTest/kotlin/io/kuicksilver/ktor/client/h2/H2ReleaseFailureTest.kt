// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    InternalKuicksilverApi::class,
    ExperimentalKuicksilverApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
    io.ktor.utils.io.InternalAPI::class,
)

package io.kuicksilver.ktor.client.h2

import io.ktor.client.plugins.websocket.WEBSOCKETS_KEY
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.url
import io.ktor.http.HttpStatusCode
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.H2ClientConnection
import io.kuicksilver.http2.runtime.H2ServerConnection
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.ktor.client.EngineEvents
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration

/**
 * A stream's release that throws (an engine callback's exception, here `onChange` in its unreserve) in the HTTP/2
 * exchange and WebSocket: it gave the stream and its slot back all the same, so `connectionReleased` still goes out; a
 * completion handler logs it at Warn instead of passing it to the uncaught-exception handler, and a call that already
 * failed keeps its own failure, the release's suppressed under it.
 */
class H2ReleaseFailureTest {
    private class Lines : KuicksilverLogger {
        val lines = ArrayList<Pair<LogLevel, Throwable?>>()

        override fun isEnabled(level: LogLevel): Boolean = true

        override fun log(
            level: LogLevel,
            message: String,
            cause: Throwable?,
        ) {
            lines += level to cause
        }
    }

    private class Fixture(
        val conn: H2Conn,
        val server: H2ServerConnection,
    ) {
        /** The next `onChange` after the last stream was unreserved throws. */
        var armed = false
        val logger = Lines()
        val events = EngineEvents(null, logger)
        val released = ArrayList<Boolean>()
    }

    private fun TestScope.clock(): () -> Long = { testScheduler.currentTime * 1_000_000 }

    private suspend fun TestScope.fixture(): Fixture {
        val toServer = ByteChannel()
        val toClient = ByteChannel()
        val close = {
            toServer.close()
            toClient.close()
        }
        val server =
            H2ServerConnection.start(
                toServer,
                toClient,
                Http2Settings(),
                backgroundScope,
                close,
                clock(),
                enableConnectProtocol = true,
            )
        var f: Fixture? = null
        val client =
            H2ClientConnection.start(
                toClient,
                toServer,
                Http2Settings(),
                backgroundScope,
                Duration.INFINITE,
                close,
                onChange = {
                    val x = f
                    if (x != null && x.armed && x.conn.client.reservedStreams == 0) {
                        x.armed = false
                        throw IllegalStateException("from onChange")
                    }
                },
                clock = clock(),
            )
        val made = Fixture(H2Conn(client, "https://example.com:443", 0), server)
        f = made
        runCurrent()
        assertTrue(client.tryReserve())
        return made
    }

    private fun request(url: String) = HttpRequestBuilder().apply { url(url) }.build()

    private fun webSocketRequest() =
        HttpRequestBuilder()
            .apply {
                url("wss://example.com/")
                attributes.put(WEBSOCKETS_KEY, WebSockets())
            }.build()

    private fun Fixture.assertWarned() {
        val (level, cause) = logger.lines.single()
        assertEquals(LogLevel.Warn, level)
        assertEquals("from onChange", cause?.message)
    }

    private fun Fixture.assertReleasedOnce() {
        assertEquals(1, released.size, "connectionReleased went out once")
        assertEquals(0, conn.client.reservedStreams, "the slot came back")
    }

    @Test fun negative_anExchangeWhoseReleaseThrowsAtTheCallsEndLogsIt() =
        runTest {
            val f = fixture()
            val call = Job()
            val response = async { h2Exchange(f.conn, request("https://example.com/"), call, f.events) { f.released += it } }
            runCurrent()
            f.server.requests
                .receive()
                .respond(200, emptyList(), endStream = false)
            runCurrent()
            assertEquals(HttpStatusCode.OK, response.await().statusCode)
            f.armed = true
            call.complete() // the handler's exception does not escape it
            runCurrent()
            f.assertReleasedOnce()
            f.assertWarned()
        }

    @Test fun negative_anExchangeThatFailedKeepsItsFailureOverTheReleases() =
        runTest {
            val f = fixture()
            val call = Job()
            val response =
                async {
                    runCatching { h2Exchange(f.conn, request("https://example.com/"), call, f.events) { f.released += it } }
                }
            runCurrent()
            f.armed = true
            f.server.requests
                .receive()
                .reset(Http2ErrorCode.INTERNAL_ERROR)
            runCurrent()
            val e = assertIs<Http2Exception.StreamReset>(response.await().exceptionOrNull())
            assertEquals("from onChange", e.suppressedExceptions.single().message)
            f.assertReleasedOnce()
            f.assertWarned()
            call.complete()
            runCurrent()
            assertEquals(1, f.released.size)
        }

    @Test fun negative_aWebSocketWhoseReleaseThrowsAtTheCallsEndLogsIt() =
        runTest {
            val f = fixture()
            val call = Job()
            val response = async { h2WebSocket(f.conn, request("wss://example.com/"), call, f.events) { f.released += it } }
            runCurrent()
            f.server.requests
                .receive()
                .respond(400, emptyList(), endStream = false)
            runCurrent()
            assertEquals(HttpStatusCode.BadRequest, response.await().statusCode)
            f.armed = true
            call.complete()
            runCurrent()
            f.assertReleasedOnce()
            f.assertWarned()
        }

    @Test fun negative_aWebSocketThatFailedKeepsItsFailureOverTheReleases() =
        runTest {
            val f = fixture()
            val call = Job()
            val response =
                async {
                    runCatching { h2WebSocket(f.conn, request("wss://example.com/"), call, f.events) { f.released += it } }
                }
            runCurrent()
            f.armed = true
            f.server.requests
                .receive()
                .reset(Http2ErrorCode.INTERNAL_ERROR)
            runCurrent()
            val e = assertIs<Http2Exception.StreamReset>(response.await().exceptionOrNull())
            assertEquals("from onChange", e.suppressedExceptions.single().message)
            f.assertReleasedOnce()
            f.assertWarned()
            call.complete()
            runCurrent()
            assertEquals(1, f.released.size)
        }

    @Test fun negative_anExchangeCancelledWhileItWaitsLogsTheReleaseFailure() =
        runTest {
            val f = fixture()
            val call = Job()
            val response = async { h2Exchange(f.conn, request("https://example.com/"), call, f.events) { f.released += it } }
            runCurrent()
            f.armed = true
            response.cancel() // the caller's cancellation (or a request timeout) is in flight: it never reports the release's
            runCurrent()
            f.assertReleasedOnce()
            f.assertWarned()
            call.complete()
            runCurrent()
            assertEquals(1, f.released.size)
        }

    @Test fun negative_anExchangeWithoutAJobKeepsItsFailureOverTheRelease() =
        runTest {
            val f = fixture()
            f.armed = true
            val e =
                assertFailsWith<IllegalStateException> {
                    h2Exchange(f.conn, request("https://example.com/"), EmptyCoroutineContext, f.events) { f.released += it }
                }
            assertEquals("a call without a Job", e.message)
            assertEquals("from onChange", e.suppressedExceptions.single().message)
            f.assertReleasedOnce()
            f.assertWarned()
        }

    @Test fun negative_aWebSocketWithoutAJobKeepsItsFailureOverTheRelease() =
        runTest {
            val f = fixture()
            f.armed = true
            val e =
                assertFailsWith<IllegalStateException> {
                    h2WebSocket(f.conn, request("wss://example.com/"), EmptyCoroutineContext, f.events) { f.released += it }
                }
            assertEquals("a call without a Job", e.message)
            assertEquals("from onChange", e.suppressedExceptions.single().message)
            f.assertReleasedOnce()
            f.assertWarned()
        }

    @Test fun negative_anOpenWebSocketWhoseCallIsCancelledLogsTheReleaseFailure() =
        runTest {
            val f = fixture()
            val call = Job()
            val context = call + StandardTestDispatcher(testScheduler)
            val response = async { h2WebSocket(f.conn, webSocketRequest(), context, f.events) { f.released += it } }
            runCurrent()
            f.server.requests
                .receive()
                .respond(200, emptyList(), endStream = false)
            runCurrent()
            assertEquals(HttpStatusCode.SwitchingProtocols, response.await().statusCode)
            f.armed = true
            call.cancel() // reset at once, from the completion handler
            runCurrent()
            f.assertReleasedOnce()
            f.assertWarned()
        }

    @Test fun negative_aWebSocketClosedInOrderLogsTheReleaseFailureAfterTheCloseWait() =
        runTest {
            val f = fixture()
            val call = Job()
            val context = call + StandardTestDispatcher(testScheduler)
            val response = async { h2WebSocket(f.conn, webSocketRequest(), context, f.events) { f.released += it } }
            runCurrent()
            val server = f.server.requests.receive()
            server.respond(200, emptyList(), endStream = false)
            runCurrent()
            val session = response.await().body as WebSocketSession
            // the server's Close (its END_STREAM held back), then the client's Close: the session ends in order
            server.sendBody(ByteReadChannel(byteArrayOf(0x88.toByte(), 0)), end = false)
            runCurrent()
            session.outgoing.send(Frame.Close())
            runCurrent()
            f.armed = true
            call.complete() // the close wait starts: no reset at once, the server's END_STREAM is waited for
            assertTrue(call.isCompleted)
            runCurrent()
            assertEquals(0, f.released.size, "the stream is held for the server's END_STREAM")
            assertTrue(server.awaitClientEnd(), "the client's END_STREAM went out, no RST_STREAM")
            server.sendBody(ByteReadChannel(ByteArray(0)), end = true)
            runCurrent()
            f.assertReleasedOnce()
            f.assertWarned()
        }

    @Test fun negative_aWebSocketWhoseCloseIsNotAnsweredLogsTheReleaseFailure() =
        runTest {
            val f = fixture()
            val call = Job()
            val context = call + StandardTestDispatcher(testScheduler)
            val response =
                async { h2WebSocket(f.conn, webSocketRequest(), context, f.events, closeWaitMillis = 1_000) { f.released += it } }
            runCurrent()
            f.server.requests
                .receive()
                .respond(200, emptyList(), endStream = false)
            runCurrent()
            val session = response.await().body as WebSocketSession
            session.outgoing.send(Frame.Close())
            runCurrent()
            assertEquals(0, f.released.size)
            f.armed = true
            testScheduler.advanceTimeBy(1_001) // the server answered neither with its Close nor with END_STREAM
            runCurrent()
            f.assertReleasedOnce()
            f.assertWarned()
            call.complete()
            runCurrent()
            assertEquals(1, f.released.size)
        }
}
