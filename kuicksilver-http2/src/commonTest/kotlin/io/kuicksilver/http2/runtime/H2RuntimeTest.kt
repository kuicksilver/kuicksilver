// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class, ExperimentalCoroutinesApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.hpack.HpackEncoder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The coroutine runtime over in-memory byte channels, under virtual time: our client against our server runtime, and
 * against a raw peer that writes frames by hand where a real server would not misbehave the way the test needs.
 */
class H2RuntimeTest {
    private val get = listOf<Pair<String, String>>()

    private class Wire {
        val toServer = ByteChannel()
        val toClient = ByteChannel()

        fun close() {
            toServer.close()
            toClient.close()
        }
    }

    private fun TestScope.clock(): () -> Long = { testScheduler.currentTime * 1_000_000 }

    private suspend fun TestScope.pair(
        clientSettings: Http2Settings = Http2Settings(),
        serverSettings: Http2Settings = Http2Settings(),
        pingInterval: Duration = Duration.INFINITE,
    ): Triple<H2ClientConnection, H2ServerConnection, Wire> {
        val w = Wire()
        val server = H2ServerConnection.start(w.toServer, w.toClient, serverSettings, backgroundScope, { w.close() }, clock())
        val client =
            H2ClientConnection.start(
                w.toClient,
                w.toServer,
                clientSettings,
                backgroundScope,
                pingInterval,
                { w.close() },
                clock = clock(),
            )
        return Triple(client, server, w)
    }

    private fun H2ClientConnection.get(path: String = "/"): H2ClientStream {
        assertTrue(tryReserve())
        return open("GET", "https", "example.com", path, get, endStream = true)
    }

    private fun CoroutineScope.serve(
        server: H2ServerConnection,
        handler: suspend (H2ServerStream) -> Unit,
    ) = launch {
        for (r in server.requests) {
            launch {
                try {
                    handler(r)
                } finally {
                    r.release()
                }
            }
        }
    }

    private suspend fun ByteReadChannel.readAll(): ByteArray = readBuffer().readByteArray()

    @Test fun requestAndResponseWithTrailers() =
        runTest {
            val (client, server, _) = pair()
            backgroundScope.serve(server) { r ->
                assertEquals("/hello", r.path)
                r.respond(200, listOf("content-type" to "text/plain"))
                r.sendBody(ByteReadChannel("hello".encodeToByteArray()), end = false)
                r.trailers(listOf("grpc-status" to "0"))
            }
            val s = client.get("/hello")
            val head = s.response()
            assertEquals(200, head.status)
            assertEquals(listOf("content-type" to "text/plain"), head.fields)
            assertEquals("hello", s.body.readAll().decodeToString())
            assertEquals(listOf("grpc-status" to "0"), s.trailers)
            s.release()
            runCurrent()
            assertEquals(0, client.reservedStreams)
        }

    @Test fun postBodyGoesWithinWindowsAndEnds() =
        runTest {
            // a body that fills the server's stream window exactly still ends (an empty END_STREAM frame needs no window)
            val (client, server, _) = pair(serverSettings = Http2Settings(initialStreamWindow = 65_536, maxStreamWindow = 65_536))
            val got =
                async {
                    server.requests.receive().let { r ->
                        r.body
                            .readAll()
                            .size
                            .also { r.respond(204, endStream = true) }
                    }
                }
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/", listOf("content-length" to "65536"), endStream = false)
            s.sendBody(ByteReadChannel(ByteArray(65_536)), stallMillis = null) { error("stall") }
            assertEquals(204, s.response().status)
            assertEquals(65_536, got.await())
            s.release()
        }

    /**
     * Flow control follows the application's reading (RFC 9113 section 5.2): a client that does not read stops the server
     * at the stream window, and reading lets the rest through. Memory on the client stays within the window.
     */
    @Test fun streamingBodyBackpressure() =
        runTest {
            val window = 65_536
            val (client, server, _) =
                pair(
                    clientSettings =
                        Http2Settings(
                            initialStreamWindow = window,
                            maxStreamWindow = window,
                            initialConnectionWindow =
                                1 shl 20,
                        ),
                )
            val total = 8 shl 20 // above what the source channel buffers by itself (1 MiB)
            var sent = 0L
            val done =
                backgroundScope.async {
                    val r = server.requests.receive()
                    r.respond(200)
                    val src = ByteChannel()
                    launch {
                        val chunk = ByteArray(4096)
                        repeat(total / chunk.size) {
                            src.writeFully(chunk)
                            src.flush()
                            sent += chunk.size
                        }
                        src.close()
                    }
                    r.sendBody(src)
                }
            val s = client.get()
            s.response()
            advanceTimeBy(10_000)
            runCurrent()
            // the server stopped near the window: what it handed over is at most the window plus what its source buffered
            assertTrue(sent < total, "the server must stop at the client's window, sent $sent")
            assertFalse(done.isCompleted)
            assertEquals(total, s.body.readAll().size)
            done.await()
            s.release()
        }

    /**
     * Section 5.1.1: identifiers cannot be reused. A connection whose last odd identifier was used takes no new request
     * (it is no longer usable, so the pool moves on) and closes once its streams are done.
     */
    @Test fun streamIdentifiersExhaustedRetireTheConnection() =
        runTest {
            val (client, server, _) = pair()
            backgroundScope.serve(server) { r -> r.respond(200, endStream = true) }
            client.rt.lock.withLock { client.rt.core.nextStreamIdForTest(Int.MAX_VALUE) } // 2^31 - 1, the last one
            val last = client.get()
            assertEquals(Int.MAX_VALUE, last.id)
            assertFalse(client.isUsable, "no identifier left: no new stream on this connection")
            assertFalse(client.tryReserve())
            assertEquals(200, last.response().status)
            last.release()
            runCurrent()
            assertTrue(client.isClosed, "the connection closes once its last stream is done")
        }

    @Test fun negative_contentLengthMismatchIsMalformed() =
        runTest {
            val (client, server, _) = pair()
            backgroundScope.serve(server) { r ->
                r.respond(200, listOf("content-length" to "10"))
                r.sendBody(ByteReadChannel("short".encodeToByteArray()))
            }
            val s = client.get()
            assertEquals(200, s.response().status)
            // RFC 9113 section 8.1.1: the content does not match content-length: the response is malformed, not complete
            assertFailsWith<Http2Exception.MalformedMessage> { s.body.readAll() }
            s.release()
        }

    @Test fun negative_resetFailsTheBodyNotEndsIt() =
        runTest {
            val (client, server, _) = pair()
            val gotPart = kotlinx.coroutines.CompletableDeferred<Unit>()
            backgroundScope.serve(server) { r ->
                r.respond(200)
                r.sendBody(ByteReadChannel("part".encodeToByteArray()), end = false)
                gotPart.await() // a reset drops what is still queued (RFC 9113 section 6.4): the part must be out first
                r.reset(Http2ErrorCode.INTERNAL_ERROR)
            }
            val s = client.get()
            s.response()
            val part = ByteArray(4)
            assertEquals(4, s.body.readAvailable(part, 0, 4))
            assertContentEquals("part".encodeToByteArray(), part)
            gotPart.complete(Unit)
            // ktor-io answers -1 for a channel closed with a cause; this body throws instead: a cut body is never complete
            val e = assertFailsWith<Http2Exception.StreamReset> { s.body.readAll() }
            assertEquals(Http2ErrorCode.INTERNAL_ERROR, e.code)
            assertFalse(e.notProcessed)
            s.release()
        }

    @Test fun cancelSendsRstStreamCancel() =
        runTest {
            val (client, server, _) = pair()
            val seen =
                async {
                    server.requests.receive().let { r ->
                        r.respond(200)
                        assertFailsWith<Http2Exception.StreamReset> { r.body.readAll() }.code
                    }
                }
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/", get, endStream = false)
            s.response()
            s.release() // the call ended with the stream unfinished both ways
            assertEquals(Http2ErrorCode.CANCEL, seen.await())
        }

    /** The engine's view of a server stream: its failure (here the client's CANCEL) reaches the handler; idle once released. */
    @Test fun serverStreamFailureReachesTheHandlerAndReleaseCounts() =
        runTest {
            val (client, server, _) = pair()
            val failure = kotlinx.coroutines.CompletableDeferred<Throwable>()
            val req =
                backgroundScope.async {
                    server.requests.receive().also { r ->
                        r.invokeOnFailure { failure.complete(it) }
                        r.respond(200)
                    }
                }
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/up", listOf("content-length" to "3"), endStream = false)
            val r = req.await()
            assertEquals("https", r.scheme)
            assertEquals(3L, r.contentLength)
            assertEquals(1, server.openRequests.value)
            s.response()
            s.cancel()
            val e = assertIs<Http2Exception.StreamReset>(failure.await())
            assertEquals(Http2ErrorCode.CANCEL, e.code)
            r.release()
            r.release() // once only
            assertEquals(0, server.openRequests.value)
            s.release()
        }

    /** RFC 9113 section 8.1: the handler is done after a complete response; the client still sending is told to stop. */
    @Test fun releasedAfterCompleteResponseTheClientIsStoppedWithNoError() =
        runTest {
            val (client, server, _) = pair()
            backgroundScope.serve(server) { r -> r.respond(200, endStream = true) }
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/", get, endStream = false)
            assertEquals(200, s.response().status)
            // the request body is not wanted: sending it ends quietly (the server stopped the stream with NO_ERROR)
            s.sendBody(ByteReadChannel(ByteArray(1 shl 20)), stallMillis = null) { error("stall") }
            assertEquals(0, s.body.readAll().size)
            s.release()
        }

    // ---- against a raw server ----

    /** A server that writes frames by hand; [read] decodes what the client wrote after its preface. */
    private class RawServer(
        val w: Wire,
    ) {
        val hpack = HpackEncoder()
        private val dec = FrameDecoder(H2.MAX_MAX_FRAME_SIZE)
        private var prefaceLeft = H2.PREFACE.size
        private val buf = ByteArray(65_536)

        suspend fun write(vararg frames: ByteArray) {
            for (f in frames) w.toClient.writeFully(f)
            w.toClient.flush()
        }

        suspend fun settings(vararg kv: Pair<Int, Long>) =
            write(FrameEncoder.settings(kv.map { it.first }.toIntArray(), kv.map { it.second }.toLongArray()))

        /** Frames the client wrote so far (without waiting for more). */
        suspend fun read(): List<Frame> {
            val out = mutableListOf<Frame>()
            while (w.toServer.availableForReadCompat() > 0) {
                val n = w.toServer.readAvailable(buf, 0, buf.size)
                var p = 0
                if (prefaceLeft > 0) {
                    val k = minOf(prefaceLeft, n)
                    prefaceLeft -= k
                    p = k
                }
                while (p < n) {
                    p += dec.feed(buf, p, n - p)
                    while (true) out += dec.next() ?: break
                }
            }
            return out
        }

        fun headers(
            id: Int,
            fields: List<Pair<String, String>>,
            endStream: Boolean,
        ): ByteArray = FrameEncoder.headers(id, hpack.encode(fields), endStream, true, -1)
    }

    private suspend fun TestScope.raw(
        pingInterval: Duration = Duration.INFINITE,
    ): Pair<RawServer, kotlinx.coroutines.Deferred<H2ClientConnection>> {
        val w = Wire()
        val r = RawServer(w)
        // the tests here talk to a server that sent its SETTINGS: the connection is handed over once they arrived
        val client =
            backgroundScope.async {
                H2ClientConnection
                    .start(
                        w.toClient,
                        w.toServer,
                        Http2Settings(),
                        backgroundScope,
                        pingInterval,
                        { w.close() },
                        clock = clock(),
                    ).also { it.rt.prefaceReceived.await() }
            }
        runCurrent()
        return r to client
    }

    /**
     * RFC 9113 section 3.4: "clients are permitted to send additional frames to the server immediately after sending the
     * client connection preface, without waiting to receive the server connection preface". The connection is usable at
     * once and the first request's HEADERS leave before the server said anything.
     */
    @Test fun firstRequestLeavesBeforeTheServerPreface() =
        runTest {
            val w = Wire()
            val srv = RawServer(w)
            val client =
                withTimeout(1.seconds) {
                    H2ClientConnection.start(
                        w.toClient,
                        w.toServer,
                        Http2Settings(),
                        backgroundScope,
                        Duration.INFINITE,
                        { w.close() },
                        clock = clock(),
                    )
                }
            assertTrue(client.isUsable)
            val s = client.get("/first")
            assertTrue(s.openedBeforeServerSettings)
            runCurrent()
            val sent = srv.read()
            val headers = sent.filterIsInstance<Frame.Headers>().single()
            assertEquals(s.id, headers.streamId)
            assertTrue(headers.endStream)
            // the server's preface and its answer come after; the request completes normally
            srv.settings()
            srv.write(srv.headers(s.id, listOf(":status" to "200"), endStream = true))
            assertEquals(200, s.response().status)
            s.release()
            val later = client.get("/later")
            assertFalse(later.openedBeforeServerSettings)
            later.release()
        }

    /**
     * A server that never sends its preface: the requests sent meanwhile fail once the preface deadline passes, the
     * connection ends with SETTINGS_TIMEOUT (RFC 9113 section 6.5.3: our SETTINGS cannot be acknowledged before the server's
     * preface) and its transport is closed. Not before the deadline.
     */
    @Test fun negative_noServerPrefaceFailsTheRequestsAtTheDeadline() =
        runTest {
            val w = Wire()
            val srv = RawServer(w)
            val client =
                H2ClientConnection.start(
                    w.toClient,
                    w.toServer,
                    Http2Settings(),
                    backgroundScope,
                    Duration.INFINITE,
                    { w.close() },
                    clock = clock(),
                    prefaceTimeout = 5.seconds,
                )
            val s = client.get()
            advanceTimeBy(4_999)
            runCurrent()
            assertTrue(client.isUsable, "before the deadline the connection stands")
            assertFalse(s.hasResponse)
            advanceTimeBy(2)
            runCurrent()
            val e = assertFailsWith<Http2Exception.ConnectionClosed> { s.response() }
            assertEquals(Http2ErrorCode.SETTINGS_TIMEOUT, e.code)
            assertFalse(e.byPeer)
            assertTrue(client.serverPrefaceMissed)
            assertFalse(client.isUsable)
            val goAway = srv.read().filterIsInstance<Frame.GoAway>().single()
            assertEquals(Http2ErrorCode.SETTINGS_TIMEOUT.code, goAway.errorCode)
            s.release()
            runCurrent()
            assertTrue(w.toServer.isClosedForWrite, "the transport is closed")
        }

    /**
     * Before the server's SETTINGS the connection grants one stream (the request that opened it): its
     * SETTINGS_MAX_CONCURRENT_STREAMS is not known yet, and streams beyond it would be refused (RFC 9113 section 5.1.2). The
     * SETTINGS raise that to the server's limit; a stream refused all the same (REFUSED_STREAM) is not processed (section
     * 8.7) and says it was opened before them.
     */
    @Test fun oneStreamUntilTheServerSettingsThenItsLimit() =
        runTest {
            val w = Wire()
            val srv = RawServer(w)
            val client =
                H2ClientConnection.start(w.toClient, w.toServer, Http2Settings(), backgroundScope, Duration.INFINITE, {
                    w.close()
                }, clock = clock())
            assertFalse(client.serverSettingsReceived)
            val a = client.get("/a")
            assertFalse(client.tryReserve(), "one stream before the server's SETTINGS")
            runCurrent()
            assertEquals(1, srv.read().filterIsInstance<Frame.Headers>().size)
            srv.settings(0x3 to 2L) // SETTINGS_MAX_CONCURRENT_STREAMS = 2
            runCurrent()
            assertTrue(client.serverSettingsReceived)
            val b = client.get("/b")
            assertFalse(b.openedBeforeServerSettings)
            assertFalse(client.tryReserve(), "two open, and the server allows two")
            srv.write(FrameEncoder.rstStream(a.id, Http2ErrorCode.REFUSED_STREAM.code))
            val e = assertFailsWith<Http2Exception.StreamReset> { a.response() }
            assertEquals(Http2ErrorCode.REFUSED_STREAM, e.code)
            assertTrue(e.notProcessed)
            assertTrue(a.openedBeforeServerSettings)
            a.release()
            runCurrent()
            assertTrue(client.tryReserve(), "below the limit again")
            client.unreserve()
            srv.write(srv.headers(b.id, listOf(":status" to "200"), endStream = true))
            assertEquals(200, b.response().status)
            b.release()
        }

    /**
     * A preface deadline longer than `settingsAckTimeout` (10 s): our SETTINGS are not taken for unacknowledged before the
     * server's preface could have come (it acknowledges only after its own, section 3.4), so the connection stands until
     * the preface deadline and then fails as a missed preface. Once the preface came, the acknowledgement gets its 10 s
     * from then.
     */
    @Test fun negative_prefaceDeadlineBeyondTheSettingsAckTimeout() =
        runTest {
            val w = Wire()
            val srv = RawServer(w)
            val client =
                H2ClientConnection.start(
                    w.toClient,
                    w.toServer,
                    Http2Settings(),
                    backgroundScope,
                    Duration.INFINITE,
                    { w.close() },
                    clock = clock(),
                    prefaceTimeout = 30.seconds,
                )
            val s = client.get()
            advanceTimeBy(29_000)
            runCurrent()
            assertTrue(client.isUsable, "no SETTINGS_TIMEOUT at 10 s while the preface may still come")
            advanceTimeBy(1_001)
            runCurrent()
            val e = assertFailsWith<Http2Exception.ConnectionClosed> { s.response() }
            assertEquals(Http2ErrorCode.SETTINGS_TIMEOUT, e.code)
            assertTrue(client.serverPrefaceMissed)
            s.release()

            // a preface that comes at 20 s: the acknowledgement is due 10 s later, not at once
            val w2 = Wire()
            val srv2 = RawServer(w2)
            val late =
                H2ClientConnection.start(
                    w2.toClient,
                    w2.toServer,
                    Http2Settings(),
                    backgroundScope,
                    Duration.INFINITE,
                    { w2.close() },
                    clock = clock(),
                    prefaceTimeout = 30.seconds,
                )
            advanceTimeBy(20_000)
            srv2.settings()
            runCurrent()
            assertTrue(late.isUsable, "the acknowledgement's time starts with the preface")
            advanceTimeBy(10_001)
            runCurrent()
            assertFalse(late.isUsable, "no acknowledgement within 10 s of the preface")
            assertFalse(late.serverPrefaceMissed)
            srv.read()
        }

    @Test fun goAwayStreamsAboveLastIdAreNotProcessed() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            val a = client.get("/a")
            val b = client.get("/b")
            runCurrent()
            srv.read()
            // RFC 9113 section 6.8: stream 3 is above the last stream the server will process
            srv.write(FrameEncoder.goAway(a.id, Http2ErrorCode.NO_ERROR.code, ByteArray(0)))
            runCurrent()
            val e = assertFailsWith<Http2Exception> { b.response() }
            assertTrue(e.notProcessed, "a stream above GOAWAY's last stream id was not processed: $e")
            assertFalse(client.isUsable)
            srv.write(srv.headers(a.id, listOf(":status" to "200"), endStream = true))
            assertEquals(200, a.response().status)
            a.release()
            b.release()
        }

    /**
     * A GOAWAY on a connection without streams closes the core at once, under the lock, while its event may still wait
     * for another thread's dispatch: whoever then finds the connection unusable must also see the GOAWAY's code (the pool
     * reads HTTP_1_1_REQUIRED from it, RFC 9113 section 7; seen too early it was null and the call failed with "the
     * server took no request", ClientH2Test.http11RequiredBeforeTheFirstRequest on the JDK 17 job).
     */
    @Test fun goAwayCodeIsKnownOnceTheConnectionIsUnusable() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            runCurrent()
            client.rt.holdDispatchForTest()
            client.rt.receiveWithoutDispatchForTest(FrameEncoder.goAway(0, Http2ErrorCode.HTTP_1_1_REQUIRED.code, ByteArray(0)))
            assertFalse(client.tryReserve())
            assertEquals(Http2ErrorCode.HTTP_1_1_REQUIRED, client.goAwayCode, "the code of the GOAWAY that made it unusable")
            client.rt.releaseDispatchForTest()
            runCurrent()
            assertEquals(Http2ErrorCode.HTTP_1_1_REQUIRED, client.goAwayCode)
        }

    /**
     * A server may send more than one GOAWAY (RFC 9113 section 6.8); a later NO_ERROR one does not take back an earlier
     * HTTP_1_1_REQUIRED (section 7): the route must still go to HTTP/1.1 only.
     */
    @Test fun http11RequiredStaysAfterALaterNoErrorGoAway() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            val a = client.get("/a")
            runCurrent()
            srv.read()
            srv.write(FrameEncoder.goAway(a.id, Http2ErrorCode.HTTP_1_1_REQUIRED.code, ByteArray(0)))
            runCurrent()
            srv.write(FrameEncoder.goAway(a.id, Http2ErrorCode.NO_ERROR.code, ByteArray(0)))
            runCurrent()
            assertEquals(Http2ErrorCode.HTTP_1_1_REQUIRED, client.goAwayCode)
            a.release()
        }

    /**
     * The core closes on a connection error at once, under the lock, while its Closed event may still wait for another
     * thread's dispatch: a response head refused in that gap fails with the connection's end, never with a made-up
     * stream reset (CANCEL).
     */
    @Test fun aResponseRefusedBeforeTheCloseIsDispatchedFailsWithTheConnectionsEnd() =
        runTest {
            val (client, server, _) = pair()
            client.get("/")
            runCurrent()
            val r = server.requests.receive()
            server.rt.holdDispatchForTest()
            // PING with a 4-byte payload: FRAME_SIZE_ERROR, a connection error (RFC 9113 section 6.7)
            server.rt.receiveWithoutDispatchForTest(byteArrayOf(0, 0, 4, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4))
            val e = assertFailsWith<Http2Exception> { r.respond(200) }
            assertIs<Http2Exception.ConnectionClosed>(e, "the connection's end, not $e")
            server.rt.releaseDispatchForTest()
            runCurrent()
        }

    /** A request on stream [id] whose field section (about 1.5 KB, literals only) is above a server's 1 KiB limit. */
    private fun oversizedRequest(id: Int): ByteArray {
        // :method GET, :scheme https, :path / (RFC 7541 appendix A), :authority without indexing, then a 1500-byte field
        val block =
            byteArrayOf(0x82.toByte(), 0x87.toByte(), 0x84.toByte(), 0x01) + hpackString("example.com") +
                byteArrayOf(0x00) + hpackString("x-big") + hpackString("b".repeat(1_500))
        return FrameEncoder.headers(id, block, true, true, -1)
    }

    /**
     * An oversized request (RFC 9113 section 8.2: answered 431) reset by the client in the same read: the stream is closed
     * before its event is dispatched, so no 431 can go. The dispatcher (here the test's thread, in a real server possibly
     * another stream's caller) does not fail, the stream is released and the connection lives on.
     */
    @Test fun oversizedRequestResetBeforeItsDispatchIsReleasedWithoutAnAnswer() =
        runTest {
            val (_, server, _) = pair(serverSettings = Http2Settings(maxHeaderListSize = 1_024))
            runCurrent()
            server.rt.holdDispatchForTest()
            server.rt.receiveWithoutDispatchForTest(oversizedRequest(1) + FrameEncoder.rstStream(1, Http2ErrorCode.CANCEL.code))
            server.rt.releaseDispatchForTest()
            runCurrent()
            server.rt.lock.withLock {
                assertEquals(0, server.rt.core.peerStreams, "the stream no longer counts toward our limit")
                assertFalse(server.rt.core.isClosed)
            }
        }

    /**
     * An oversized request from a client whose own SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 section 6.5.2) is too small for
     * the 431 head: the stream is reset instead, released, and the connection lives on.
     */
    @Test fun oversizedRequestToAClientThatCannotTakeThe431IsReset() =
        runTest {
            val (_, server, _) =
                pair(clientSettings = Http2Settings(maxHeaderListSize = 8), serverSettings = Http2Settings(maxHeaderListSize = 1_024))
            runCurrent()
            server.rt.holdDispatchForTest()
            server.rt.receiveWithoutDispatchForTest(oversizedRequest(1))
            server.rt.releaseDispatchForTest()
            // (before the client reads the reset: stream 1 is one it never opened, which ends its side of this test's wiring)
            server.rt.lock.withLock {
                assertEquals(0, server.rt.core.peerStreams, "the stream no longer counts toward our limit")
                assertFalse(server.rt.core.isClosed)
            }
        }

    /**
     * RFC 9113 section 8.1: a server may answer before the whole request and then stop it with RST_STREAM NO_ERROR; the
     * client keeps the response (its content included, even when the reset arrives before the application read it) and
     * its sending stops without an error.
     */
    @Test fun completeResponseThenNoErrorResetKeepsTheResponse() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/", get, endStream = false)
            val body = ByteChannel()
            val sending = backgroundScope.async { s.sendBody(body, stallMillis = null) { error("stall") } }
            runCurrent()
            srv.write(
                srv.headers(s.id, listOf(":status" to "200"), endStream = false),
                FrameEncoder.data(s.id, "early".encodeToByteArray(), 0, 5, true),
                FrameEncoder.rstStream(s.id, Http2ErrorCode.NO_ERROR.code),
            )
            runCurrent()
            assertEquals(200, s.response().status)
            assertEquals("early", s.body.readAll().decodeToString())
            body.writeFully(ByteArray(1000))
            body.close()
            sending.await() // returns quietly: the server asked us to stop, without an error
            s.release()
        }

    /**
     * A reset with an error after the response's END_STREAM (the server's handler released the stream with the request
     * still coming): the request's sending fails, but the response that arrived complete stays complete, even when the
     * reset is dispatched before the application read the content.
     */
    @Test fun completeResponseThenErrorResetKeepsTheBody() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/", get, endStream = false)
            val body = ByteChannel()
            val sending = backgroundScope.async { runCatching { s.sendBody(body, stallMillis = null) { error("stall") } } }
            runCurrent()
            srv.write(
                srv.headers(s.id, listOf(":status" to "200"), endStream = false),
                FrameEncoder.data(s.id, "early".encodeToByteArray(), 0, 5, true),
                FrameEncoder.rstStream(s.id, Http2ErrorCode.CANCEL.code),
            )
            runCurrent()
            assertEquals(200, s.response().status)
            assertEquals("early", s.body.readAll().decodeToString())
            body.close()
            assertIs<Http2Exception.StreamReset>(sending.await().exceptionOrNull())
            s.release()
        }

    /**
     * The peer's reset closes the stream in the core while its event is still waiting for another thread's dispatch, and
     * the body's sender reaches its END_STREAM in that gap: the core refuses ("stream 1 is closed"). That refusal must
     * never become the stream's failure: the sender waits for the reset's event and the call fails with the reset
     * (found by the integration matrix: an IllegalStateException reached the application).
     */
    @Test fun negative_bodyEndAfterAPendingResetFailsWithTheReset() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/", get, endStream = false)
            runCurrent()
            client.rt.beforeEndStreamForTest = {
                client.rt.beforeEndStreamForTest = null
                client.rt.holdDispatchForTest()
                client.rt.receiveWithoutDispatchForTest(FrameEncoder.rstStream(s.id, Http2ErrorCode.HTTP_1_1_REQUIRED.code))
            }
            val sending =
                backgroundScope.async {
                    runCatching {
                        s.sendBody(
                            ByteReadChannel("x".encodeToByteArray()),
                            null,
                        ) { error("stall") }
                    }
                }
            runCurrent()
            client.rt.releaseDispatchForTest()
            runCurrent()
            val sent = sending.await().exceptionOrNull()
            assertIs<Http2Exception.StreamReset>(sent, "the sender fails with the reset, not the core's refusal: $sent")
            val e = assertFailsWith<Http2Exception.StreamReset> { s.response() }
            assertEquals(Http2ErrorCode.HTTP_1_1_REQUIRED, e.code)
            s.release()
        }

    @Test fun refusedStreamIsNotProcessed() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            val a = client.get()
            runCurrent()
            srv.write(FrameEncoder.rstStream(a.id, Http2ErrorCode.REFUSED_STREAM.code))
            val e = assertFailsWith<Http2Exception.StreamReset> { a.response() }
            assertTrue(e.notProcessed) // section 8.7: REFUSED_STREAM means nothing was processed
            a.release()
        }

    @Test fun negative_pushPromiseIsProtocolError() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings(0x4 to 65_535L)
            val client = deferred.await()
            val a = client.get()
            runCurrent()
            srv.read() // our SETTINGS (ENABLE_PUSH = 0) and the request
            srv.write(FrameEncoder.settingsAck())
            runCurrent()
            srv.write(
                FrameEncoder.pushPromise(
                    a.id,
                    2,
                    srv.hpack.encode(
                        listOf(
                            ":method" to "GET",
                            ":scheme" to "https",
                            ":authority" to "example.com",
                            ":path" to "/x",
                        ),
                    ),
                    true,
                ),
            )
            runCurrent()
            // RFC 9113 sections 6.6, 8.4: SETTINGS_ENABLE_PUSH = 0 was acknowledged, so PUSH_PROMISE is a connection error
            val e = assertFailsWith<Http2Exception.ConnectionClosed> { a.response() }
            assertEquals(Http2ErrorCode.PROTOCOL_ERROR, e.code)
            val goAway = srv.read().filterIsInstance<Frame.GoAway>().single()
            assertEquals(Http2ErrorCode.PROTOCOL_ERROR.code, goAway.errorCode)
            a.release()
        }

    /**
     * A transport failure the engine maps to a connection error (RFC 9113 section 9.2.1: a TLS renegotiation is a connection
     * error of type PROTOCOL_ERROR): GOAWAY with that code goes out on the output, which still works, and the streams fail
     * with the code and the transport's reason, not as a lost connection.
     */
    @Test fun negative_transportFailureMappedToAConnectionErrorSendsGoAway() =
        runTest {
            class Renegotiated : kotlinx.io.IOException("the peer attempted a TLS renegotiation")
            val w = Wire()
            val srv = RawServer(w)
            val deferred =
                backgroundScope.async {
                    H2ClientConnection.start(
                        w.toClient,
                        w.toServer,
                        Http2Settings(),
                        backgroundScope,
                        Duration.INFINITE,
                        { w.close() },
                        clock = clock(),
                        connectionErrorOf = { e ->
                            if (generateSequence(e) { it.cause }.any { it is Renegotiated }) Http2ErrorCode.PROTOCOL_ERROR else null
                        },
                    )
                }
            runCurrent()
            srv.settings()
            val client = deferred.await()
            val a = client.get()
            runCurrent()
            srv.read()
            w.toClient.cancel(Renegotiated()) // the TLS layer failed the input; the output stays open
            runCurrent()
            val e = assertFailsWith<Http2Exception.ConnectionClosed> { a.response() }
            assertEquals(Http2ErrorCode.PROTOCOL_ERROR, e.code)
            assertFalse(e.byPeer)
            assertTrue("renegotiation" in e.message.orEmpty(), "the reason reaches the call: ${e.message}")
            val goAway = srv.read().filterIsInstance<Frame.GoAway>().single()
            assertEquals(Http2ErrorCode.PROTOCOL_ERROR.code, goAway.errorCode)
            assertFalse(client.isUsable)
            a.release()
        }

    @Test fun negative_pingTimeoutClosesConnection() =
        runTest {
            val (srv, deferred) = raw(pingInterval = 1.seconds)
            srv.settings()
            val client = deferred.await()
            val a = client.get()
            runCurrent()
            // the server reads but never answers our PINGs: one interval to the first PING, one more to see it unanswered
            advanceTimeBy(2_100)
            runCurrent()
            assertTrue(srv.read().any { it is Frame.Ping && !it.ack })
            val e = assertFailsWith<Http2Exception.ConnectionClosed> { a.response() }
            assertTrue("PING" in (e.message ?: ""), e.message)
            assertTrue(client.isClosed || !client.isUsable)
            a.release()
        }

    @Test fun healthCheckIsAnsweredOrTimesOut() =
        runTest {
            val (client, _, _) = pair()
            assertTrue(client.checkHealth(1_000))
            val (srv, deferred) = raw()
            srv.settings()
            val silent = deferred.await()
            runCurrent()
            // the raw server reads but answers no PING: false once the bound has passed (virtual time)
            assertFalse(silent.checkHealth(1_000))
        }

    @Test fun concurrentHealthChecksShareOnePing() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            runCurrent()
            srv.read()
            val checks = (1..40).map { backgroundScope.async { client.checkHealth(1_000) } }
            runCurrent()
            val pings = srv.read().filterIsInstance<Frame.Ping>().filter { !it.ack }
            assertEquals(1, pings.size, "one PING for forty concurrent checks")
            srv.write(FrameEncoder.ping(true, pings.single().payload))
            runCurrent()
            assertTrue(checks.all { it.await() })
        }

    /** The check's owner is cancelled: the callers sharing it get no verdict, so one of them checks again (no false "dead"). */
    @Test fun cancelledHealthCheckOwnerGivesNoVerdict() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            runCurrent()
            srv.read()
            val owner = backgroundScope.async { client.checkHealth(1_000) }
            runCurrent()
            val sharer = backgroundScope.async { client.checkHealth(1_000) }
            runCurrent()
            owner.cancel()
            runCurrent()
            // the sharer sent its own PING: answer every PING written so far
            for (p in srv.read().filterIsInstance<Frame.Ping>().filter { !it.ack }) srv.write(FrameEncoder.ping(true, p.payload))
            runCurrent()
            assertTrue(sharer.await(), "an answered PING, not the cancelled owner's 'no', decides")
        }

    @Test fun pingAnsweredKeepsTheConnection() =
        runTest {
            val (client, server, _) = pair(pingInterval = 1.seconds)
            backgroundScope.serve(server) { r -> r.respond(200, endStream = true) }
            advanceTimeBy(10_000)
            runCurrent()
            assertTrue(client.isUsable)
            val s = client.get()
            assertEquals(200, s.response().status)
            s.release()
        }

    @Test fun negative_serverHpackBombFailsTheRequestOnly() =
        runTest {
            val (srv, deferred) = raw()
            srv.settings()
            val client = deferred.await()
            val a = client.get()
            runCurrent()
            // one 4000-byte entry in the dynamic table, then referenced 100 times: 15 bytes on the wire, 400 KB decoded, above
            // our 64 KiB SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 section 10.5.1)
            val block = byteArrayOf(0x88.toByte(), 0x40) + hpackString("x-bomb") + hpackString("b".repeat(4000)) // RFC 7541 section 6.2.1
            srv.write(FrameEncoder.headers(a.id, block, false, true, -1))
            runCurrent()
            a.response()
            val b = client.get()
            runCurrent()
            val index = 62 // the newest dynamic entry (RFC 7541 section 2.3.3)
            val bomb = byteArrayOf(0x88.toByte()) + ByteArray(100) { (0x80 or index).toByte() } // :status 200, then x-bomb x100
            srv.write(FrameEncoder.headers(b.id, bomb, true, true, -1))
            runCurrent()
            assertFailsWith<Http2Exception.FieldSectionTooLarge> { b.response() }
            assertTrue(client.isUsable, "a field section too large fails its request, not the connection")
            a.release()
            b.release()
        }

    /**
     * Only the core's own refusal of a sender's call means "the stream ended under us". An IllegalStateException out of the
     * event dispatch that follows the call (here the engine's `onChange` callback, run by the sender's thread because the
     * event was waiting when its call returned) is not one: taken for a refusal, the sender waited for a stream failure that
     * never came, or sent the chunk the core had already taken a second time.
     */
    @Test fun negative_dispatchFailureIsNotTakenForTheCoresRefusal() =
        runTest {
            var armed = false
            val w = Wire()
            val server = H2ServerConnection.start(w.toServer, w.toClient, Http2Settings(), backgroundScope, { w.close() }, clock())
            val client =
                H2ClientConnection.start(
                    w.toClient,
                    w.toServer,
                    Http2Settings(),
                    backgroundScope,
                    Duration.INFINITE,
                    { w.close() },
                    onChange = { if (armed) throw IllegalStateException("from onChange") },
                    clock = clock(),
                )
            val got =
                backgroundScope.async {
                    runCatching {
                        server.requests
                            .receive()
                            .body
                            .readAll()
                    }
                }
            assertTrue(client.tryReserve())
            val s = client.open("POST", "https", "example.com", "/", get, endStream = false)
            runCurrent()
            // a SETTINGS from the server whose event (SettingsChanged, which calls onChange) waits for the next dispatcher
            client.rt.receiveWithoutDispatchForTest(FrameEncoder.settings(IntArray(0), LongArray(0)))
            armed = true
            val e =
                withTimeout(10.seconds) {
                    assertFailsWith<IllegalStateException> {
                        s.sendBody(ByteReadChannel("once".encodeToByteArray()), stallMillis = null) { error("stall") }
                    }
                }
            assertEquals("from onChange", e.message)
            armed = false
            runCurrent()
            // the chunk went out once; the stream was then reset (the sender failed), so the body is not complete
            assertIs<Http2Exception.StreamReset>(got.await().exceptionOrNull())
            s.release()
        }
}

/** An RFC 7541 string literal without Huffman coding: a 7-bit prefixed length (section 5.1), then the octets. */
private fun hpackString(v: String): ByteArray {
    val out = ArrayList<Byte>()
    var n = v.length
    if (n < 127) {
        out += n.toByte()
    } else {
        out += 127
        n -= 127
        while (n >= 128) {
            out += ((n and 0x7f) or 0x80).toByte()
            n = n ushr 7
        }
        out += n.toByte()
    }
    return out.toByteArray() + v.encodeToByteArray()
}

/** Bytes readable without suspending. */
@OptIn(io.ktor.utils.io.InternalAPI::class)
private fun ByteReadChannel.availableForReadCompat(): Int = readBuffer.let { if (it.exhausted()) 0 else 1 }
