// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

class LimitsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A field section above the peer's SETTINGS_MAX_FIELD_SECTION_SIZE fails locally, before a stream is opened (RFC 9114 section 4.2.2). */
    @Test fun peerMaxFieldSectionSizeEnforcedOnSend() =
        h3Test {
            H3Pair.open(serverSettings = http3Settings { maxFieldSectionSize = 1000 }).useScoped { p ->
                withTimeout(5.seconds) { p.client.peerSettings.first { it != null } }
                val e =
                    assertFailsWith<Http3Exception.FieldSectionTooLarge> {
                        p.client.request(get(headers = Http3Headers.of("x-big" to "v".repeat(2000))))
                    }
                assertEquals(1000L, e.limit)
                val server =
                    launch {
                        p.server
                            .acceptRequest()
                            .respond(204)
                            .finish()
                    }
                val ok = p.client.request(get())
                assertEquals(204, ok.status)
                assertEquals(0L, ok.streamId, "the refused request opened no stream")
                server.joinWithin("the server's answer to the request after the refused one")
            }
        }

    /** The server's response above the client's SETTINGS_MAX_FIELD_SECTION_SIZE fails `respond` instead of being sent. */
    @Test fun responseAbovePeerLimitFailsRespond() =
        h3Test {
            H3Pair.open(clientSettings = http3Settings { maxFieldSectionSize = 1000 }).useScoped { p ->
                withTimeout(5.seconds) { p.server.peerSettings.first { it != null } }
                val resp = async { runCatching { p.client.request(get()) } }
                val r = p.server.acceptWithin()
                val e =
                    assertFailsWith<Http3Exception.FieldSectionTooLarge> {
                        r.respond(200, Http3Headers.of("x-big" to "v".repeat(2000)))
                    }
                assertEquals(1000L, e.limit)
                assertTrue(resp.awaitWithin("the client's request").isFailure, "the client never got the oversized response")
            }
        }

    /** Server trailers above the client's limit reset the stream (H3_INTERNAL_ERROR) instead of leaving it half-open. */
    @Test fun trailersAbovePeerLimitResetTheStream() =
        h3Test {
            H3Pair.open(clientSettings = http3Settings { maxFieldSectionSize = 1000 }).useScoped { p ->
                withTimeout(5.seconds) { p.server.peerSettings.first { it != null } }
                // the reset may reach the client before or after its response head: `request` itself or the body read
                // fails, and either failure stays inside this coroutine (an async child that throws would cancel the test)
                val outcome =
                    async {
                        runCatching {
                            val response = p.client.request(get())
                            response.body.readAllBytes()
                        }
                    }
                val r = p.server.acceptWithin()
                val w = r.respond(200)
                w.output.writeFully("hello".encodeToByteArray())
                w.output.flush()
                val e =
                    assertFailsWith<Http3Exception.FieldSectionTooLarge> {
                        w.finish(Http3Headers.of("x-big" to "v".repeat(2000)))
                    }
                assertEquals(1000L, e.limit)
                val body = withTimeout(5.seconds) { outcome.await() }
                assertTrue(body.isFailure, "the client saw a complete body ${body.getOrNull()?.decodeToString()}")
            }
        }

    /**
     * Request trailers above the server's limit: the caller of `request` or of the response body sees FieldSectionTooLarge.
     * The client sends HEADERS and DATA, then resets the stream (H3_REQUEST_CANCELLED) when its trailers are refused; a
     * reset that reaches the server before it read the HEADERS discards them (RFC 9000 section 3.2) and no request
     * surfaces, which is how a cancelled request ends (RFC 9114 section 4.1.1). The server side here serves whatever
     * surfaces and the assertions are the caller's; [requestTrailersRefusedWhenTheResetWinsTheRace] forces that ordering
     * (the Windows JVM gate timed out waiting for a request the reset had removed).
     */
    @Test fun requestTrailersAbovePeerLimitReachTheCaller() = requestTrailersAbovePeerLimit(resetFirst = false)

    /** [requestTrailersAbovePeerLimitReachTheCaller] with the server reading the first request only once its reset arrived. */
    @Test fun requestTrailersRefusedWhenTheResetWinsTheRace() = requestTrailersAbovePeerLimit(resetFirst = true)

    private fun requestTrailersAbovePeerLimit(resetFirst: Boolean) =
        h3Test {
            H3Pair.open(serverSettings = http3Settings { maxFieldSectionSize = 1000 }).useScoped { p ->
                withTimeout(5.seconds) { p.client.peerSettings.first { it != null } }
                if (resetFirst) p.server.session.beforeRequestHeadersForTest = { st -> if (st.id == 0L) awaitPeerReset(st) }

                fun post(
                    path: String,
                    before: CompletableDeferred<Unit>? = null,
                ) = http3Request("POST", "server.test", path) {
                    body = ByteReadChannel("ping")
                    trailers = {
                        before?.await()
                        Http3Headers.of("x-big" to "v".repeat(2000))
                    }
                }
                val responded = CompletableDeferred<Unit>()
                val seen = ArrayList<String>()
                // "/read-first" waits for the whole request before it answers; "/answer-first" answers, then reads
                val server =
                    launch {
                        while (true) {
                            val r = p.server.acceptRequest()
                            seen += r.path.orEmpty()
                            launch {
                                if (r.path == "/answer-first") {
                                    val w = r.respond(200)
                                    responded.complete(Unit)
                                    runCatching { r.body.readAllBytes() }
                                    runCatching { w.finish() }
                                } else {
                                    runCatching { r.body.readAllBytes() }
                                    runCatching { r.respond(200).finish() }
                                }
                            }
                        }
                    }
                // the server waits for the whole request before it answers: `request` fails
                val e1 = withTimeout(5.seconds) { runCatching { p.client.request(post("/read-first")) }.exceptionOrNull() }
                assertTrue(e1 is Http3Exception.FieldSectionTooLarge, "request() failed with $e1")
                // the server answers first (the trailers wait for it): the response body fails
                val e2 =
                    withTimeout(5.seconds) {
                        runCatching {
                            val resp = p.client.request(post("/answer-first", responded))
                            resp.body.readAllBytes()
                            resp.trailers.await()
                        }.exceptionOrNull()
                    }
                assertTrue(e2 is Http3Exception.FieldSectionTooLarge, "the response failed with $e2")
                server.cancel()
                if (resetFirst) assertEquals(listOf("/answer-first"), seen, "a request reset before its HEADERS were read surfaced")
            }
        }

    /**
     * A request stream reset before its HEADERS were read surfaces no request and leaves nothing behind: the stream is
     * retired and its MAX_STREAMS credit returns. With two bidirectional streams allowed, five such requests in a row and a
     * normal one after them all get a stream; a stream that was never credited back would leave the third waiting.
     */
    @Test fun negative_requestResetBeforeItsHeadersAreReadIsRetired() =
        h3Test {
            H3Pair
                .open(
                    serverSettings = http3Settings { maxFieldSectionSize = 1000 },
                    serverQuic = quicConfig { maxBidiStreams = 2 },
                ).useScoped { p ->
                    withTimeout(5.seconds) { p.client.peerSettings.first { it != null } }
                    p.server.session.beforeRequestHeadersForTest = { st -> if (st.id < 20L) awaitPeerReset(st) }
                    repeat(5) { i ->
                        val e =
                            withTimeoutOrNull(5.seconds) {
                                runCatching {
                                    p.client.request(
                                        http3Request("POST", "server.test", "/cancelled-$i") {
                                            body = ByteReadChannel("ping")
                                            trailers = { Http3Headers.of("x-big" to "v".repeat(2000)) }
                                        },
                                    )
                                }.exceptionOrNull()
                            } ?: fail("request $i got no stream within 5 s: an earlier reset stream was not credited back")
                        assertTrue(e is Http3Exception.FieldSectionTooLarge, "request $i failed with $e")
                    }
                    val served =
                        async {
                            val r = p.server.acceptRequest()
                            r.respond(204).finish()
                            r.path
                        }
                    val ok =
                        withTimeoutOrNull(5.seconds) { p.client.request(get("/ok")) }
                            ?: fail("the request after the resets got no stream within 5 s")
                    assertEquals(204, ok.status)
                    assertEquals(20L, ok.streamId, "streams 0..16 went to the cancelled requests")
                    assertEquals("/ok", served.awaitWithin("the server's next request"), "a cancelled request surfaced first")
                    assertEquals(
                        null,
                        p.server.session.requests
                            .tryReceive()
                            .getOrNull()
                            ?.path,
                        "a cancelled request was queued",
                    )
                }
        }

    private val big = (0 until 7).map { "x-big-$it" to "v".repeat(10_000) } // 7 x 10039 = 70273 decoded bytes > 65536

    /** The response a raw client gets on [streamId]: status and the STOP_SENDING code if one came. */
    @Test fun negative_h3DecodedFieldSectionTooLarge() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET + big))
                peerMayHaveClosed { st.output.flush() }
                val resp = st.input.readAllBytes() // a 431 response, then FIN
                val h = FrameHeaders.parse(resp, 0, resp.size)!!
                assertEquals(FrameType.HEADERS, h.type)
                val fields =
                    io.kuicksilver.http3.qpack.QpackDecoder(0, 0, 65_536).decode(
                        st.id,
                        resp.copyOfRange(
                            h.headerSize,
                            h.headerSize + h.length.toInt(),
                        ),
                    )
                assertEquals(":status" to "431", (fields as io.kuicksilver.http3.qpack.DecodeResult.Decoded).fields.first())
                val stopped =
                    runCatching {
                        repeat(200) {
                            st.output.writeFully(ByteArray(1000))
                            st.output.flush()
                            kotlinx.coroutines.delay(5)
                        }
                    }.exceptionOrNull()
                assertEquals(
                    Http3ErrorCode.EXCESSIVE_LOAD,
                    generateSequence(stopped) {
                        it.cause
                    }.filterIsInstance<QuicException.StreamError.Stopped>().first().code,
                )
                assertTrue(!server.closed.isCompleted)
            }
        }

    /** Receive side: a raw client (which ignores our SETTINGS) sends 70 KiB of trailers; a compliant sender refuses them first. */
    @Test fun negative_h3TrailersTooLarge() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                // the server may stop the stream (STOP_SENDING) once it has read past its limit, before the rest of the 70 KiB
                // is out: the raw client's write then fails, which is the refusal under test, not an error of the test
                runCatching {
                    st.output.writeFully(raw.headers(st.id, post) + raw.data("x".encodeToByteArray()) + raw.headers(st.id, big))
                    st.output.flushAndClose()
                }
                val r = server.acceptWithin()
                val e =
                    runCatching {
                        r.body.readAllBytes()
                        r.trailers.await()
                    }.exceptionOrNull()
                assertTrue(e is Http3Exception.FieldSectionTooLarge, "got $e")
                // the server answers 431 or stops the stream; either way the client does not see a 2xx
                val resp = runCatching { st.input.readAllBytes() }.getOrNull()
                if (resp != null && resp.isNotEmpty()) {
                    val h = FrameHeaders.parse(resp, 0, resp.size)!!
                    val fields =
                        io.kuicksilver.http3.qpack.QpackDecoder(0, 0, 65_536).decode(
                            st.id,
                            resp.copyOfRange(h.headerSize, h.headerSize + h.length.toInt()),
                        )
                    assertEquals(":status" to "431", (fields as io.kuicksilver.http3.qpack.DecodeResult.Decoded).fields.first())
                }
            }
        }

    /** Receive side: a raw server (which ignores our SETTINGS) answers with 70 KiB of fields; a compliant sender refuses them first. */
    @Test fun responseHeadersTooLargeOnClient() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                launch {
                    val st = s.acceptBidi()
                    st.input.readAllBytes()
                    // the client stops the stream on the oversized section, possibly before this write returns
                    peerMayHaveClosed {
                        st.output.writeFully(raw.headers(st.id, listOf(":status" to "200") + big))
                        st.output.flushAndClose()
                    }
                }
                assertFailsWith<Http3Exception.FieldSectionTooLarge> { client.request(get()) }
            }
        }

    private fun statusOf(
        streamId: Long,
        resp: ByteArray,
    ): String {
        val h = FrameHeaders.parse(resp, 0, resp.size)!!
        assertEquals(FrameType.HEADERS, h.type)
        val d =
            io.kuicksilver.http3.qpack.QpackDecoder(0, 0, 65_536).decode(
                streamId,
                resp.copyOfRange(h.headerSize, h.headerSize + h.length.toInt()),
            )
        return (d as io.kuicksilver.http3.qpack.DecodeResult.Decoded).fields.first { it.first == ":status" }.second
    }

    /**
     * One field value above the string ceiling (65,600 bytes at the default 64 KiB limit) is a stream error: 431 and the
     * connection keeps serving (RFC 9204 section 7.4); before, it closed the connection with QPACK_DECOMPRESSION_FAILED.
     */
    @Test fun negative_h3SingleOversizedFieldIs431NotConnectionError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET + ("x-big" to "v".repeat(65_600))))
                peerMayHaveClosed { st.output.flush() }
                assertEquals("431", statusOf(st.id, st.input.readAllBytes()))
                assertTrue(!server.closed.isCompleted)
                // another request on the same connection is served
                val served =
                    launch {
                        server
                            .acceptRequest()
                            .respond(204)
                            .finish()
                    }
                val st2 = c.openBidi()
                st2.output.writeFully(raw.headers(st2.id, GET))
                st2.output.flushAndClose()
                assertEquals("204", statusOf(st2.id, st2.input.readAllBytes()))
                served.joinWithin("the server's answer to the second request")
                assertTrue(!server.closed.isCompleted)
            }
        }

    /** Client side: a response with one oversized field fails that request only; the next request on the connection succeeds. */
    @Test fun singleOversizedResponseFieldFailsOnlyItsRequest() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                launch {
                    val st = s.acceptBidi()
                    st.input.readAllBytes()
                    peerMayHaveClosed {
                        st.output.writeFully(raw.headers(st.id, listOf(":status" to "200", "set-cookie" to "c".repeat(70_000))))
                        st.output.flushAndClose()
                    }
                    val st2 = s.acceptBidi()
                    st2.input.readAllBytes()
                    st2.output.writeFully(raw.headers(st2.id, listOf(":status" to "204")))
                    st2.output.flushAndClose()
                }
                assertFailsWith<Http3Exception.FieldSectionTooLarge> { client.request(get()) }
                assertEquals(204, client.request(get()).status)
                assertTrue(!client.closed.isCompleted)
            }
        }

    /** A raised SETTINGS_MAX_FIELD_SECTION_SIZE also raises the string ceiling: one 100 KB value is accepted under 1 MiB. */
    @Test fun raisedMaxFieldSectionSizeAcceptsLargeSingleValue() =
        h3Test {
            H3Pair.open(serverSettings = http3Settings { maxFieldSectionSize = 1L shl 20 }).useScoped { p ->
                withTimeout(5.seconds) { p.client.peerSettings.first { it != null } }
                val value = "v".repeat(100_000)
                val server =
                    async {
                        val r = p.server.acceptRequest()
                        r.respond(204).finish()
                        r.headers["x-big"]
                    }
                assertEquals(204, p.client.request(get(headers = Http3Headers.of("x-big" to value))).status)
                assertEquals(value, server.awaitWithin("the server's request"))
            }
        }

    @Test fun headersFrameLengthAboveCapRejectedWithoutReading() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                // a HEADERS frame announcing 1 GiB, followed by a few bytes only
                val st = c.openBidi()
                val hdr = ByteArray(16)
                val n = FrameHeaders.write(FrameType.HEADERS, 1L shl 30, hdr, 0)
                st.output.writeFully(hdr.copyOf(n) + ByteArray(100))
                peerMayHaveClosed { st.output.flush() }
                val resp = st.input.readAllBytes()
                assertTrue(resp.isNotEmpty()) // a 431, not a hang
                assertTrue(!server.closed.isCompleted)
            }
        }

    /** A HEADERS frame's declared length reserves no memory; only the bytes that arrived are held. */
    @Test fun negative_headersDeclaredLengthNotPreallocated() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val hdr = ByteArray(16)
                val n = FrameHeaders.write(FrameType.HEADERS, 128L * 1024, hdr, 0) // at the 2 x maxFieldSectionSize cap
                repeat(100) {
                    val st = c.openBidi()
                    st.output.writeFully(hdr.copyOf(n) + ByteArray(5))
                    st.output.flush()
                }
                kotlinx.coroutines.delay(500)
                val held = withContext(server.session.dispatcher) { server.session.bufferedHeaderBytes }
                assertTrue(held < 100L * 4096, "the server holds $held bytes for 100 streams that sent 5 payload bytes each")
                assertTrue(!server.closed.isCompleted)
            }
        }

    @Test fun negative_h3ReservedFrameHugeLength() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val hdr = ByteArray(16)
                val n = FrameHeaders.write(0x21, 1L shl 40, hdr, 0)
                st.output.writeFully(raw.headers(st.id, GET) + hdr.copyOf(n) + ByteArray(10))
                peerMayHaveClosed { st.output.flushAndClose() }
                val r = server.acceptWithin()
                // skipped as it streams (no 1 TiB buffer); the FIN inside it is a connection error H3_FRAME_ERROR (RFC 9114 section 7.1)
                val e = assertFailsWith<Http3Exception.Protocol> { r.body.readAllBytes() }
                assertEquals(Http3ErrorCode.FRAME_ERROR, e.h3Code)
                assertEquals(Http3ErrorCode.FRAME_ERROR, peerSawClose(c))
            }
        }

    /** The next request, or a failure that says the server never got one (instead of the test's 30 s timeout). */
    private suspend fun Http3Connection.acceptWithin(): io.kuicksilver.http3.Http3ServerRequest =
        withTimeoutOrNull(WAIT) { acceptRequest() } ?: fail("no request reached the server within $WAIT")

    private suspend fun Job.joinWithin(what: String) {
        withTimeoutOrNull(WAIT) { join() } ?: fail("$what did not finish within $WAIT")
    }

    private suspend fun <T> Deferred<T>.awaitWithin(what: String): T {
        val done = withTimeoutOrNull(WAIT) { Result.success(await()) } ?: fail("$what did not finish within $WAIT")
        return done.getOrThrow() // a null result is a result, not a timeout
    }

    /** Returns once the peer's RESET_STREAM for [st] arrived (its input fails from then on). */
    private suspend fun awaitPeerReset(st: io.kuicksilver.quic.QuicStream) {
        withTimeoutOrNull(WAIT) { while (st.input.closedCause == null) delay(1) } ?: fail("no reset for stream ${st.id} within $WAIT")
    }

    private companion object {
        val WAIT = 5.seconds
    }
}
