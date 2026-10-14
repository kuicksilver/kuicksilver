// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.ContinuationInterceptor
import kotlin.test.BeforeTest
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal fun get(
    path: String = "/",
    headers: Http3Headers = Http3Headers.Empty,
) = http3Request("GET", "server.test", path) {
    this.headers = headers
}

class RequestTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun getRoundTrip() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    assertEquals("GET", r.method)
                    assertEquals("/hello", r.path)
                    assertEquals("server.test", r.authority)
                    val w = r.respond(200, Http3Headers.of("content-type" to "text/plain"))
                    w.output.writeStringUtf8("hello")
                    w.finish()
                }
                val resp = p.client.request(get("/hello"))
                assertEquals(200, resp.status)
                assertEquals("text/plain", resp.headers["content-type"])
                assertEquals("hello", resp.body.readAllBytes().decodeToString())
                assertNull(resp.trailers.await())
            }
        }

    @Test fun postBodyBackpressure() =
        h3Test {
            val size = 5 * 1024 * 1024
            val payload = ByteArray(size) { (it % 251).toByte() }
            H3Pair.open().useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    delay(200) // the client must wait on flow control, not buffer everything
                    val got = r.body.readAllBytes()
                    val w = r.respond(200)
                    w.output.writeFully(got)
                    w.finish()
                }
                val body = ByteChannel()
                launch {
                    body.writeFully(payload)
                    body.flushAndClose()
                }
                val resp =
                    p.client.request(
                        http3Request("POST", "server.test", "/echo") {
                            this.body = body
                        },
                    )
                assertContentEquals(payload, resp.body.readAllBytes())
            }
        }

    @Test fun trailersBothWays() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    assertEquals("ping", r.body.readAllBytes().decodeToString())
                    assertEquals("c1", r.trailers.await()?.get("x-checksum"))
                    val w = r.respond(200)
                    w.output.writeStringUtf8("pong")
                    w.finish(Http3Headers.of("x-checksum" to "s1"))
                }
                val resp =
                    p.client.request(
                        http3Request("POST", "server.test", "/") {
                            body = ByteReadChannel("ping")
                            trailers = {
                                Http3Headers.of("x-checksum" to "c1")
                            }
                        },
                    )
                assertEquals("pong", resp.body.readAllBytes().decodeToString())
                assertEquals("s1", resp.trailers.await()?.get("x-checksum"))
            }
        }

    @Test fun informational103ThenFinal() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val server =
                    launch {
                        val r = p.server.acceptRequest()
                        r.sendInformational(
                            103,
                            Http3Headers.of("link" to "</style.css>; rel=preload"),
                        )
                        r.respond(204).finish()
                    }
                val hints = ArrayList<Pair<Int, String?>>()
                val resp =
                    p.client.request(
                        http3Request("GET", "server.test", "/") {
                            onInformational = { s, h ->
                                hints +=
                                    s to h["link"]
                            }
                        },
                    )
                assertEquals(listOf<Pair<Int, String?>>(103 to "</style.css>; rel=preload"), hints)
                assertEquals(204, resp.status)
                server.join() // the 204 arrives before finish() returns: closing earlier races the server's FIN
            }
        }

    /** A slow `onInformational` must not stall the connection: it runs on the caller's dispatcher, not the session's. */
    @Test fun onInformationalRunsOffConnectionDispatcher() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val server =
                    launch {
                        val r = p.server.acceptRequest()
                        r.sendInformational(103, Http3Headers.of("link" to "</a.css>; rel=preload"))
                        r.respond(204).finish()
                    }
                var seen: Any? = null
                p.client.request(
                    http3Request("GET", "server.test", "/") {
                        onInformational = { _, _ ->
                            seen = currentCoroutineContext()[ContinuationInterceptor]
                        }
                    },
                )
                server.join()
                assertNotNull(seen)
                assertNotSame<Any?>(p.client.session.dispatcher, seen)
            }
        }

    /** The request's `trailers` callback runs on the caller's dispatcher, not the session's. */
    @Test fun trailersCallbackRunsOffConnectionDispatcher() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val server =
                    launch {
                        val r = p.server.acceptRequest()
                        r.body.readAllBytes()
                        assertEquals("c1", r.trailers.await()?.get("x-checksum"))
                        r.respond(204).finish()
                    }
                var seen: Any? = null
                val resp =
                    p.client.request(
                        http3Request("POST", "server.test", "/") {
                            body = ByteReadChannel("ping")
                            trailers = {
                                seen = currentCoroutineContext()[ContinuationInterceptor]
                                Http3Headers.of("x-checksum" to "c1")
                            }
                        },
                    )
                assertEquals(204, resp.status)
                server.join()
                assertNotNull(seen)
                assertNotSame<Any?>(p.client.session.dispatcher, seen)
            }
        }

    @Test fun tooManyInformationalIsExcessiveLoad() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val server =
                    launch {
                        val r = p.server.acceptRequest()
                        runCatching {
                            repeat(6) { r.sendInformational(103) }
                            r.respond(200).finish()
                        }
                        p.server
                            .acceptRequest()
                            .respond(200)
                            .finish()
                    }
                val e = assertFailsWith<Http3Exception.Protocol> { p.client.request(get()) }
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, e.h3Code)
                assertEquals(200, p.client.request(get()).status) // the connection lives on
                server.join() // the 200 arrives before finish() returns: closing earlier races the server's FIN
            }
        }

    @Test fun contentLengthMismatchIsMessageError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(
                    raw.headers(
                        st.id,
                        listOf(
                            ":method" to "POST",
                            ":scheme" to "https",
                            ":authority" to "a",
                            ":path" to "/",
                            "content-length" to "10",
                        ),
                    ) +
                        raw.data(ByteArray(4)),
                )
                peerMayHaveClosed { st.output.flushAndClose() }
                val r = server.acceptRequest()
                val e = assertFailsWith<Http3Exception.MessageError> { r.body.readAllBytes() }
                assertEquals(st.id, e.streamId)
                assertTrue(!server.closed.isCompleted)
            }
        }

    @Test fun malformedRequestResetsStreamOnly() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val bad = c.openBidi()
                bad.output.writeFully(
                    raw.headers(
                        bad.id,
                        listOf(
                            ":method" to "GET",
                            ":scheme" to "https",
                            ":authority" to "a",
                        ),
                    ),
                )
                peerMayHaveClosed { bad.output.flushAndClose() } // no :path
                val e = assertFailsWith<QuicException.StreamError.Reset> { bad.input.readAllBytes() }
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, e.code)
                val good = c.openBidi()
                good.output.writeFully(raw.headers(good.id, GET))
                good.output.flushAndClose()
                val r = server.acceptRequest()
                assertEquals(good.id, r.streamId)
                r.respond(200).finish()
            }
        }

    @Test fun unknownFramesSkippedOnRequestStream() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(
                    raw.frame(0x21, ByteArray(3000)) +
                        raw.headers(
                            st.id,
                            GET.map {
                                if (it.first ==
                                    ":method"
                                ) {
                                    it.first to "POST"
                                } else {
                                    it
                                }
                            },
                        ) +
                        raw.frame(0x40, ByteArray(10)) +
                        raw.data("abc".encodeToByteArray()) +
                        raw.frame(FrameType.grease(7), ByteArray(0)),
                )
                st.output.flushAndClose()
                val r = server.acceptRequest()
                assertEquals("abc", r.body.readAllBytes().decodeToString())
            }
        }

    /** RFC 9114 section 7.2.8 / 8.1: unknown frames are skipped, but a flood of them is useless work that spends glitch tokens. */
    @Test fun unknownFramesOnRequestStreamSpendGlitchTokens() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val one = raw.frame(0x22, ByteArray(0)) // unknown, not a reserved (GREASE) type
                val flood = ByteArray(one.size * 1001)
                for (i in 0 until 1001) one.copyInto(flood, i * one.size)
                // the close may land while the flood is still being flushed: that is the outcome under test
                runCatching {
                    st.output.writeFully(flood)
                    st.output.flush()
                }
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, peerSawClose(c))
            }
        }

    /** Reserved frame types (0x1f * N + 0x21, RFC 9114 section 7.2.8) are GREASE a peer is meant to send: they cost no glitch token. */
    @Test fun greaseFramesOnRequestStreamsAreFree() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                // twice the bucket, in one write: the flood test's 1001 unknown frames close the connection
                val flood =
                    (0 until 2002)
                        .map {
                            raw.frame(
                                io.kuicksilver.http3.frame.FrameType
                                    .grease(it.toLong()),
                                ByteArray(0),
                            )
                        }.reduce { a, b -> a + b }
                st.output.writeFully(flood + raw.headers(st.id, GET))
                st.output.flushAndClose()
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                r.respond(204).finish()
                assertTrue(st.input.readAllBytes().isNotEmpty())
                assertTrue(!server.closed.isCompleted, "GREASE frames closed the connection")
            }
        }

    /** RFC 9114 section 4.1.2 / RFC 9110 sections 9.3.2, 15.3.5, 15.4.5: DATA on a response that has no content is malformed. */
    private suspend fun CoroutineScope.dataOnBodilessResponseIsMessageError(
        method: String,
        status: Int,
    ) {
        QuicPair.open().useScoped { q ->
            val (c, s) = q.connect()
            val client = Http3Connection.client(c)
            val raw = RawPeer(s)
            raw.openControl()
            client.peerSettings.filterNotNull().first()
            val served =
                async {
                    val st = s.acceptBidi()
                    // the client stops the stream as soon as it sees the DATA; on a fast host that lands before this close returns
                    peerMayHaveClosed {
                        st.output.writeFully(
                            raw.headers(st.id, listOf(":status" to status.toString())) + raw.data("hello".encodeToByteArray()),
                        )
                        st.output.flushAndClose()
                    }
                    st
                }
            val resp = client.request(http3Request(method, "server.test", "/"))
            assertEquals(status, resp.status)
            val e = assertFailsWith<Http3Exception.MessageError> { resp.body.readAllBytes() }
            assertEquals(served.await().id, e.streamId)
            assertTrue(!client.closed.isCompleted, "a stream error, not a connection error")
        }
    }

    @Test fun dataInHeadResponseIsMessageError() = h3Test { dataOnBodilessResponseIsMessageError("HEAD", 200) }

    @Test fun dataIn204ResponseIsMessageError() = h3Test { dataOnBodilessResponseIsMessageError("GET", 204) }

    @Test fun dataIn304ResponseIsMessageError() = h3Test { dataOnBodilessResponseIsMessageError("GET", 304) }

    @Test fun cancelledRequestStopsStreamAndConnectionSurvives() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val streamGone = CompletableDeferred<Throwable>()
                launch {
                    val r = p.server.acceptRequest()
                    val w = r.respond(200)
                    try {
                        while (true) {
                            w.output.writeFully(ByteArray(16_384))
                            w.output.flush()
                            delay(5)
                        }
                    } catch (
                        e: Throwable,
                    ) {
                        streamGone.complete(e)
                    }
                }
                val resp = p.client.request(get("/stream"))
                withTimeoutOrNull(100.milliseconds) { resp.body.readAllBytes() } // the caller times out mid-body
                resp.cancel()
                val e = withTimeout(5.seconds) { streamGone.await() }
                assertEquals(
                    Http3ErrorCode.REQUEST_CANCELLED,
                    generateSequence(e) {
                        it.cause
                    }.filterIsInstance<Http3Exception.Protocol>().firstOrNull()?.h3Code,
                    "got ${generateSequence(e) { it.cause }.toList()}",
                )
                val next =
                    launch {
                        val r = p.server.acceptRequest()
                        r.respond(200).finish()
                    }
                assertEquals(200, p.client.request(get("/next")).status)
                next.join()
            }
        }

    @Test fun requestCoroutineCancelledResetsStream() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val serverSaw = CompletableDeferred<Throwable>()
                launch {
                    val r = p.server.acceptRequest()
                    try {
                        r.body.readAllBytes()
                        delay(10_000)
                    } catch (
                        e: Throwable,
                    ) {
                        serverSaw.complete(e)
                    }
                }
                val body = ByteChannel()
                val job =
                    async {
                        p.client.request(
                            http3Request("POST", "server.test", "/") {
                                this.body = body
                            },
                        )
                    }
                body.writeFully(ByteArray(100))
                body.flush()
                delay(200)
                job.cancel()
                val e = withTimeout(5.seconds) { serverSaw.await() }
                assertEquals(
                    Http3ErrorCode.REQUEST_CANCELLED,
                    generateSequence(e) { it.cause }.filterIsInstance<Http3Exception.Protocol>().first().h3Code,
                )
            }
        }

    /** RFC 9114 section 4.1.2 / RFC 9110 section 8.6: a non-numeric or conflicting content-length is malformed; identical repeats collapse to one. */
    @Test fun invalidOrConflictingContentLengthIsMessageError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()

                suspend fun post(vararg lengths: String): QuicException.StreamError.Reset? {
                    val st = c.openBidi()
                    st.output.writeFully(
                        raw.headers(
                            st.id,
                            listOf(":method" to "POST", ":scheme" to "https", ":authority" to "a", ":path" to "/") +
                                lengths.map { "content-length" to it },
                        ),
                    )
                    peerMayHaveClosed {
                        st.output.writeFully(raw.data(byteArrayOf(1, 2, 3, 4)))
                        st.output.flushAndClose()
                    } // the server may stop the stream on the HEADERS alone
                    return runCatching { st.input.readAllBytes() }.exceptionOrNull() as? QuicException.StreamError.Reset
                }
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, post("abc")?.code, "non-numeric content-length")
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, post("abc", "4")?.code, "one invalid value among several")
                assertEquals(Http3ErrorCode.MESSAGE_ERROR, post("1", "4")?.code, "conflicting values")
                launch {
                    val r = server.acceptRequest()
                    assertEquals(
                        1,
                        r.headers.fields.count { it.first == "content-length" },
                        "repeated identical values collapse: ${r.headers.fields}",
                    )
                    assertEquals(4, r.body.readAllBytes().size)
                    r.respond(200).finish()
                }
                assertNull(post("4", "4"), "identical repeats are accepted")
            }
        }

    /** RFC 9114 section 4.1.2: a response to HEAD may carry a content-length without a body. */
    @Test fun headResponseWithContentLength() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    assertEquals("HEAD", r.method)
                    r
                        .respond(
                            200,
                            Http3Headers.of("content-length" to "5"),
                        ).finish()
                }
                val resp = p.client.request(http3Request("HEAD", "server.test", "/"))
                assertEquals(200, resp.status)
                assertEquals("5", resp.headers["content-length"])
                assertEquals(0, resp.body.readAllBytes().size)
                assertNull(resp.trailers.await())
            }
        }

    /** A response field the validator rejects must not leave the stream half-open: the stream is reset and the client sees an error. */
    @Test fun invalidResponseFieldResetsStream() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    assertFailsWith<IllegalArgumentException> {
                        r.respond(
                            200,
                            Http3Headers.of("x-a" to "v "),
                        )
                    }
                    assertFailsWith<IllegalStateException> { r.respond(200) }
                } // the stream was reset: the request is over
                val e =
                    withTimeoutOrNull(3.seconds) {
                        runCatching {
                            p.client
                                .request(get("/"))
                                .body
                                .readAllBytes()
                        }.exceptionOrNull()
                    }
                assertIs<Http3Exception>(e, "the client sees the reset instead of hanging: $e")
            }
        }

    /** A request body the application never reads is stopped with H3_NO_ERROR once the response is complete (RFC 9114 section 4.1). */
    @Test fun unreadBodyIsStoppedAfterResponse() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val served = CompletableDeferred<io.kuicksilver.http3.Http3ServerRequest>()
                launch {
                    val r = p.server.acceptRequest()
                    r.respond(404).finish()
                    served.complete(r)
                }
                val body = ByteChannel()
                launch {
                    runCatching {
                        repeat(128) {
                            body.writeFully(ByteArray(64 * 1024))
                            body.flush()
                        }
                        body.flushAndClose()
                    }
                } // chunks: the channel stays open while the uploader waits
                val resp =
                    p.client.request(
                        http3Request("POST", "server.test", "/") {
                            this.body = body
                        },
                    )
                assertEquals(404, resp.status)
                val r = served.await()
                assertEquals(
                    true,
                    withTimeoutOrNull(3.seconds) {
                        while (r.body.closedCause ==
                            null
                        ) {
                            delay(10)
                        }
                        true
                    },
                    "the unread body is dropped once the response is complete",
                )
                // what the server read before dropping the body is bounded by the pump's buffer and the QUIC windows, not by the body size
                delay(300)
                assertTrue(
                    p.server.quic.stats.bytesReceived < 3L * 1024 * 1024,
                    "server read ${p.server.quic.stats.bytesReceived} bytes of an 8 MiB body it never consumed",
                )
                // The uploader is told to stop with H3_NO_ERROR (RFC 9114 section 4.1), not left blocked on flow control
                val stopped =
                    withTimeoutOrNull(3.seconds) {
                        while (body.closedCause ==
                            null
                        ) {
                            delay(10)
                        }
                        generateSequence(body.closedCause) { it.cause }.firstNotNullOfOrNull { it as? QuicException.StreamError.Stopped }
                    }
                assertEquals(
                    Http3ErrorCode.NO_ERROR,
                    stopped?.code,
                    "the client's body send ends with STOP_SENDING H3_NO_ERROR, got ${body.closedCause}",
                )
            }
        }

    /**
     * Answered-but-unread bodies are stopped, so their streams close and the peer gets its stream credit back.
     * This relies on kuicksilver-quic retiring a stopped receive half once its final size is known: a stopped StreamInput
     * never reads again, so the stream cannot count as closed through a read.
     */
    @Test fun unreadBodiesDoNotExhaustStreamCredit() =
        h3Test {
            H3Pair.open(serverQuic = quicConfig { maxBidiStreams = 3 }).useScoped { p ->
                launch {
                    while (true) {
                        val r = p.server.acceptRequest()
                        r.respond(404).finish()
                    }
                }
                repeat(6) { i ->
                    val body = ByteChannel()
                    launch {
                        runCatching {
                            body.writeFully(ByteArray(4 * 1024 * 1024))
                            body.flushAndClose()
                        }
                    }
                    val resp =
                        withTimeoutOrNull(
                            5.seconds,
                        ) {
                            p.client.request(
                                http3Request("POST", "server.test", "/$i") {
                                    this.body = body
                                },
                            )
                        }
                    assertEquals(404, resp?.status, "request $i is answered")
                    resp!!.body.readAllBytes()
                }
                coroutineContext.cancelChildren()
            }
        }
}
