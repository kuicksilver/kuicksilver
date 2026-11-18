// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.qpack.QpackEncoder
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.qlog.AsyncQlogSink
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The HTTP/3 events of the qlog trace (draft-ietf-quic-qlog-h3-events-04, next to the transport's qlog 0.3 events): a real
 * exchange, both vantage points, checked against the schema offline ([QlogSchema]), plus the attacks on the feature: field
 * values that must not leak, huge and malformed frames, concurrent streams, and sinks that fail or stall.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class H3QlogTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val secrets = listOf("Bearer s3cr3t-token", "session=c00kie-value", "q=private-query", "x-trailer-secret-value")

    private fun traced(sink: QlogSink) = quicConfig { qlog = sink }

    /** Waits until both endpoints' traces ended (the connections released them), so their records are final. */
    private suspend fun awaitClosed(sink: MemoryQlogSink) =
        awaitCondition("both traces closed", timeout = kotlin.time.Duration.parse("10s")) {
            sink.traces.size == 2 && sink.traces.all { it.closed }
        }

    private fun events(
        sink: MemoryQlogSink,
        role: TlsRole,
    ): List<Map<String, Any?>> = QlogSchema.check(sink.trace(role).records)

    private fun List<Map<String, Any?>>.named(name: String) = filter { it["name"] == name }.map { it["data"] as Map<*, *> }

    private fun Map<*, *>.frame() = this["frame"] as Map<*, *>

    private fun Map<*, *>.num(key: String) = (this[key] as Double).toLong()

    /** A GET and a POST with a body and trailers both ways, then a PRIORITY_UPDATE and a GOAWAY. */
    private suspend fun exchange(sink: MemoryQlogSink) {
        H3Pair.open(serverQuic = traced(sink), clientQuic = traced(sink)).useScoped { p ->
            launch {
                val get = p.server.acceptRequest()
                get.respond(200, Http3Headers.of("content-type" to "text/plain", "set-cookie" to secrets[1])).let {
                    it.output.writeStringUtf8("hello")
                    it.finish()
                }
                val post = p.server.acceptRequest()
                assertEquals("ping", post.body.readAllBytes().decodeToString())
                post.respond(201).finish(Http3Headers.of("x-checksum" to secrets[3]))
            }
            val r1 =
                p.client.request(
                    http3Request("GET", "server.test", "/a?${secrets[2]}") {
                        headers = Http3Headers.of("authorization" to secrets[0], "cookie" to secrets[1])
                    },
                )
            assertEquals("hello", r1.body.readAllBytes().decodeToString())
            val r2 =
                p.client.request(
                    http3Request("POST", "server.test", "/b") {
                        body = ByteReadChannel("ping")
                        trailers = { Http3Headers.of("x-checksum" to secrets[3]) }
                    },
                )
            r2.updatePriority(StreamPriority(2, true))
            r2.body.readAllBytes()
            assertNotNull(r2.trailers.await())
            p.server.goAway()
            awaitCondition("the client saw the GOAWAY") { p.client.session.goAwayReceived.value != null }
        }
        awaitClosed(sink)
    }

    @Test fun aRealExchangeFollowsTheSchemaAtBothEnds() =
        h3Test {
            val sink = MemoryQlogSink()
            exchange(sink)
            for (role in listOf(TlsRole.Client, TlsRole.Server)) {
                val e = events(sink, role)
                // the critical streams, ours and the peer's (RFC 9114 section 6.2)
                for (owner in listOf("local", "remote")) {
                    val types = e.named("http:stream_type_set").filter { it["owner"] == owner }.map { it["stream_type"] }
                    assertTrue(types.containsAll(listOf("control", "qpack_encode", "qpack_decode")), "$role $owner: $types")
                    assertTrue(e.named("http:parameters_set").any { it["owner"] == owner }, "$role parameters_set $owner")
                }
                val created = e.named("http:frame_created")
                val parsed = e.named("http:frame_parsed")
                assertTrue(created.any { it.frame()["frame_type"] == "settings" }, "$role: SETTINGS sent")
                assertTrue(parsed.any { it.frame()["frame_type"] == "settings" }, "$role: SETTINGS read")
                for (list in listOf(created, parsed)) {
                    // request stream 0: HEADERS and DATA; stream 4: HEADERS, DATA, trailers
                    assertTrue(list.count { it.num("stream_id") == 0L && it.frame()["frame_type"] == "headers" } == 1, "$role $list")
                    assertTrue(list.count { it.num("stream_id") == 4L && it.frame()["frame_type"] == "headers" } == 2, "$role $list")
                    assertTrue(list.any { it.frame()["frame_type"] == "data" }, "$role DATA")
                }
                // the transport's events and ours are one trace: packets are there too
                assertTrue(e.any { it["name"] == "transport:packet_sent" })
            }
            val client = events(sink, TlsRole.Client)
            val server = events(sink, TlsRole.Server)
            // the request as sent and as read: names always, the method kept, the path redacted
            val sentHead = client.named("http:frame_created").first { it.num("stream_id") == 0L && it.frame()["frame_type"] == "headers" }
            val readHead = server.named("http:frame_parsed").first { it.num("stream_id") == 0L && it.frame()["frame_type"] == "headers" }
            for (h in listOf(sentHead, readHead)) {
                val fields = (h.frame()["headers"] as List<*>).map { it as Map<*, *> }.associate { it["name"] to it["value"] }
                assertEquals("GET", fields[":method"])
                assertEquals(H3Qlog.REDACTED, fields[":path"])
                assertEquals(H3Qlog.REDACTED, fields["authorization"])
                assertEquals(H3Qlog.REDACTED, fields["cookie"])
                assertTrue(h.num("length") > 0 && (h["raw"] as Map<*, *>).num("length") > h.num("length"), "$h")
            }
            assertTrue("\"name\":\":status\",\"value\":\"200\"" in sink.trace(TlsRole.Client).records.joinToString(""), "the status kept")
            // PRIORITY_UPDATE (RFC 9218): not in the draft, so a frame type of its own through the $HTTPFrame extension point
            val prio = client.named("http:frame_created").single { it.frame()["frame_type"] == "priority_update" }
            assertEquals(4.0, prio.frame()["stream_id"])
            assertEquals("u=2, i", prio.frame()["priority_field_value"])
            assertTrue(server.named("http:frame_parsed").any { it.frame()["priority_field_value"] == "u=2, i" })
            // GOAWAY: the server's first (2^62-4) as sent and as read
            assertTrue(
                server.named("http:frame_created").any {
                    it.frame()["frame_type"] == "goaway" &&
                        it.frame()["id"] == 4611686018427387900.0
                },
            )
            assertTrue(client.named("http:frame_parsed").any { it.frame()["frame_type"] == "goaway" })
        }

    /** CWE-532: with the default sink nothing of a header or trailer value but the protocol's own tokens reaches the trace. */
    @Test fun negative_fieldValuesNeverReachADefaultTrace() =
        h3Test {
            val sink = MemoryQlogSink()
            exchange(sink)
            for (t in sink.traces) {
                val all = t.records.joinToString("")
                for (s in secrets) assertFalse(s in all, "${t.role} trace holds '$s'")
                assertTrue("\"name\":\"authorization\"" in all && "\"name\":\"set-cookie\"" in all, "${t.role}: the names stay")
            }
        }

    @Test fun fieldValuesAreLoggedWhenTheSinkOptsIn() =
        h3Test {
            val sink = MemoryQlogSink(logHeaderValues = true)
            exchange(sink)
            val client = sink.trace(TlsRole.Client).records.joinToString("")
            val server = sink.trace(TlsRole.Server).records.joinToString("")
            for (s in secrets) assertTrue(s in client && s in server, "'$s' as sent and as read")
            QlogSchema.check(sink.trace(TlsRole.Client).records)
        }

    /** No sink: no recorder, so the HTTP/3 layer formats nothing (the hot path only reads a null). */
    @Test fun anUntracedConnectionHasNoRecorder() =
        h3Test {
            H3Pair.open().use { p ->
                assertNull(p.client.session.qlog)
                assertNull(p.server.session.qlog)
            }
        }

    /** A field section near the limit, values escaped: one record, still valid JSON. */
    @Test fun hugeHeadersStayOneValidRecord() =
        h3Test {
            val sink = MemoryQlogSink(logHeaderValues = true)
            // quotes and backslashes to escape, near the 64 KiB field section limit
            val big = buildString { repeat(10_000) { append("\"\\ab") } }
            H3Pair.open(serverQuic = traced(sink), clientQuic = traced(sink)).useScoped { p ->
                launch {
                    p.server
                        .acceptRequest()
                        .respond(204)
                        .finish()
                }
                val r = p.client.request(http3Request("GET", "server.test", "/") { headers = Http3Headers.of("x-big" to big) })
                assertEquals(204, r.status)
            }
            awaitClosed(sink)
            val server = events(sink, TlsRole.Server)
            val head = server.named("http:frame_parsed").first { it.frame()["frame_type"] == "headers" && it.num("stream_id") == 0L }
            val value = (head.frame()["headers"] as List<*>).map { it as Map<*, *> }.single { it["name"] == "x-big" }["value"] as String
            assertEquals(big, value)
        }

    /** A HEADERS frame longer than we read is logged without its fields, and the stream's refusal follows. */
    @Test fun aHeadersFrameTooLargeIsLoggedWithoutFields() =
        h3Test {
            val sink = MemoryQlogSink()
            QuicPair.open(traced(sink)).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, http3Settings { maxFieldSectionSize = 100 })
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(VarInt.encode(FrameType.HEADERS) + VarInt.encode(100_000))
                peerMayHaveClosed { st.output.flush() }
                awaitCondition("the oversized HEADERS logged") {
                    sink.trace(TlsRole.Server).records.any { "\"headers\":[]" in it && "\"payload_length\":100000" in it }
                }
                server.close()
            }
            QlogSchema.check(sink.trace(TlsRole.Server).records)
        }

    /** Unknown and reserved frames and stream types (RFC 9114 sections 6.2, 7.2.8, 9) are in the trace by their numbers. */
    @Test fun unknownFramesAndStreamTypesAreLoggedByNumber() =
        h3Test {
            val sink = MemoryQlogSink()
            QuicPair.open(traced(sink)).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.control.output.writeFully(raw.frame(0x2abc, ByteArray(3)) + raw.frame(FrameType.grease(7), ByteArray(0)))
                raw.control.output.flush()
                raw.uni(0x3fff, ByteArray(1))
                raw.uni(FrameType.grease(2), ByteArray(0))
                awaitCondition("the frames and streams logged") {
                    val all = sink.trace(TlsRole.Server).records.joinToString("")
                    "\"frame_type_value\":${0x2abc}" in all && "{\"frame_type\":\"reserved\",\"length\":0}" in all &&
                        "\"stream_type_value\":${0x3fff}" in all && "\"stream_type\":\"reserved\"" in all
                }
                server.close()
            }
            val e = events(sink, TlsRole.Server).named("http:frame_parsed").map { it.frame() }
            // h3-events-04 section 5.2.9 (frame_type_value) and 5.2.8 (a reserved frame has its length only)
            assertTrue(e.any { it["frame_type"] == "unknown" && it["frame_type_value"] == 0x2abc.toDouble() }, "$e")
            assertTrue(e.any { it["frame_type"] == "reserved" && it["length"] == 0.0 }, "$e")
            val types =
                events(
                    sink,
                    TlsRole.Server,
                ).named("http:stream_type_set").filter { it["owner"] == "remote" }.map { it["stream_type"] }
            assertTrue(types.containsAll(listOf("unknown", "reserved")), "$types")
        }

    /** A frame the control stream must not carry ends the connection; the trace holds it and stays valid to its end. */
    @Test fun anErrorMidStreamLeavesAValidTrace() =
        h3Test {
            val sink = MemoryQlogSink()
            QuicPair.open(traced(sink)).use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                // DATA on the control stream: H3_FRAME_UNEXPECTED (RFC 9114 section 7.2.1), its payload never arrives
                raw.control.output.writeFully(VarInt.encode(FrameType.DATA) + VarInt.encode(1000) + ByteArray(10))
                peerMayHaveClosed { raw.control.output.flush() }
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, peerSawClose(c))
            }
            awaitCondition("the server's trace closed") { sink.trace(TlsRole.Server).closed }
            val e = events(sink, TlsRole.Server)
            assertTrue(e.named("http:frame_parsed").any { it.frame()["frame_type"] == "data" && it.num("length") == 1000L }, "$e")
            assertTrue(e.any { it["name"] == "connectivity:connection_closed" }, "the close is in the trace")
        }

    /** A stream that ends inside a frame (H3_FRAME_ERROR, RFC 9114 section 7.1): nothing half-written in the trace. */
    @Test fun aStreamEndingInsideAFrameLeavesAValidTrace() =
        h3Test {
            val sink = MemoryQlogSink()
            QuicPair.open(traced(sink)).use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.control.output.writeFully(VarInt.encode(FrameType.GOAWAY))
                peerMayHaveClosed { raw.control.output.flushAndClose() }
                peerSawClose(c)
            }
            awaitCondition("the server's trace closed") { sink.trace(TlsRole.Server).closed }
            QlogSchema.check(sink.trace(TlsRole.Server).records)
        }

    /**
     * QPACK (RFC 9204): the state of both dynamic tables as they change, and a field section that waits for an insert, then
     * gets it (`qpack:state_updated`, `qpack:stream_state_updated`).
     */
    @Test fun qpackStateAndBlockedStreamsAreLogged() =
        h3Test {
            val sink = MemoryQlogSink()
            QuicPair.open(traced(sink)).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, http3Settings { enableQpackDynamicTable() })
                val raw = RawPeer(c)
                raw.openControl()
                val encoderStream = raw.uni(StreamType.QPACK_ENCODER)
                val enc = QpackEncoder()
                enc.onPeerSettings(4096, 16)
                val st = c.openBidi()
                val block = enc.encode(st.id, GET + ("x-custom" to "late-insert-value"))
                val inserts = enc.drainEncoderStream()
                st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, block))
                st.output.flushAndClose()
                val accepted = async { server.acceptRequest() }

                fun has(s: String) = sink.trace(TlsRole.Server).records.any { s in it }
                awaitCondition("the section blocked") { has("\"stream_id\":${st.id},\"state\":\"blocked\"") }
                encoderStream.output.writeFully(inserts)
                encoderStream.output.flush()
                accepted.await().respond(204).finish()
                awaitCondition("the section unblocked") { has("\"stream_id\":${st.id},\"state\":\"unblocked\"") }
                awaitCondition("the peer's table logged") { has("\"owner\":\"remote\",\"dynamic_table_capacity\":4096") }
                server.close()
            }
            val e = events(sink, TlsRole.Server).named("qpack:state_updated").filter { it["owner"] == "remote" }
            assertTrue(e.any { it.num("current_insert_count") >= 1 }, "$e")
        }

    /**
     * `http:frame_created` follows the write: a response HEADERS frame whose write failed (the client stopped the request
     * stream before the server answered) is not in the trace (ADR-0021).
     */
    @Test fun negative_aFrameWhoseWriteFailedIsNotCreated() =
        h3Test {
            val sink = MemoryQlogSink()
            QuicPair.open(traced(sink)).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val streams = kotlinx.coroutines.channels.Channel<io.kuicksilver.quic.QuicStream>(1)
                server.session.beforeRequestHeadersForTest = { st -> streams.send(st) }
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET))
                st.output.flush()
                val request = withTimeout(5.seconds) { server.acceptRequest() }
                val serverSide = streams.receive()
                st.stopSending(Http3ErrorCode.REQUEST_CANCELLED)
                awaitOutputStopped(serverSide)
                assertTrue(runCatching { request.respond(200) }.isFailure, "the response's write failed")
                server.close()
            }
            awaitCondition("the server's trace closed") { sink.trace(TlsRole.Server).closed }
            val created = sink.trace(TlsRole.Server).records.filter { "http:frame_created" in it && "\"stream_id\":0," in it }
            assertTrue(created.isEmpty(), "the HEADERS frame whose write failed: $created")
            QlogSchema.check(sink.trace(TlsRole.Server).records)
        }

    /** Many streams at once on several threads: every record whole, one per line, each frame once. */
    @Test fun concurrentStreamsNeverInterleaveRecords() =
        h3Test {
            val sink = MemoryQlogSink(logHeaderValues = true)
            val n = 40
            H3Pair.open(serverQuic = traced(sink), clientQuic = traced(sink)).useScoped { p ->
                launch {
                    repeat(n) {
                        val r = p.server.acceptRequest()
                        launch(Dispatchers.Default) {
                            val w = r.respond(200)
                            repeat(5) { w.output.writeStringUtf8("chunk-of-${r.path}-") }
                            w.finish()
                        }
                    }
                }
                (0 until n)
                    .map { i ->
                        async(Dispatchers.Default) {
                            val r = p.client.request(http3Request("GET", "server.test", "/$i") { headers = Http3Headers.of("x-n" to "$i") })
                            r.body.readAllBytes()
                        }
                    }.awaitAll()
            }
            awaitClosed(sink)
            for (role in listOf(TlsRole.Client, TlsRole.Server)) {
                val e = events(sink, role)
                val heads =
                    e
                        .named(
                            if (role ==
                                TlsRole.Client
                            ) {
                                "http:frame_created"
                            } else {
                                "http:frame_parsed"
                            },
                        ).filter { it.frame()["frame_type"] == "headers" }
                val paths =
                    heads
                        .flatMap {
                            (it.frame()["headers"] as List<*>).map { f ->
                                f as Map<*, *>
                            }
                        }.filter { it["name"] == ":path" }
                assertEquals((0 until n).map { "/$it" }.toSet(), paths.map { it["value"] }.toSet(), "$role: every request once")
                assertEquals(n, paths.size)
            }
        }

    /** A sink that throws on the first HTTP/3 event: tracing stops, the connection and its requests go on. */
    @Test fun negative_aThrowingSinkLeavesTheConnectionAlone() =
        h3Test {
            val sink = MemoryQlogSink { if ("\"name\":\"http:" in it) throw IllegalStateException("disk full") }
            H3Pair.open(serverQuic = traced(sink), clientQuic = traced(sink)).useScoped { p ->
                launch {
                    repeat(3) {
                        val r = p.server.acceptRequest()
                        r.respond(200).let { w ->
                            w.output.writeStringUtf8("ok")
                            w.finish()
                        }
                    }
                }
                repeat(
                    3,
                ) {
                    assertEquals(
                        "ok",
                        p.client
                            .request(http3Request("GET", "server.test", "/"))
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                }
                assertFalse(
                    p.client.session.qlog!!
                        .enabled,
                    "tracing stopped",
                )
            }
            awaitClosed(sink)
            for (t in sink.traces) assertTrue(t.records.none { "\"name\":\"http:" in it })
        }

    /**
     * A sink that does not take records (its writer stalled) behind [AsyncQlogSink]: requests complete while it is stuck,
     * records beyond the queue are dropped, and what it writes once it moves is whole.
     */
    @Test fun aStalledSinkNeverHoldsTheConnection() =
        runBlocking {
            val release = CompletableDeferred<Unit>()
            val inner = MemoryQlogSink { runBlocking { release.await() } }
            val sink = AsyncQlogSink(inner, queueCapacity = 64)
            try {
                h3Test {
                    H3Pair.open(serverQuic = traced(sink), clientQuic = traced(sink)).useScoped { p ->
                        launch {
                            repeat(20) {
                                val r = p.server.acceptRequest()
                                r.respond(200).let { w ->
                                    w.output.writeFully(ByteArray(2000))
                                    w.finish()
                                }
                            }
                        }
                        repeat(
                            20,
                        ) {
                            assertEquals(
                                2000,
                                p.client
                                    .request(http3Request("GET", "server.test", "/"))
                                    .body
                                    .readAllBytes()
                                    .size,
                            )
                        }
                    }
                }
                assertTrue(sink.dropped > 0, "the stalled sink lost records, not requests")
            } finally {
                release.complete(Unit)
                sink.flush()
                sink.close()
            }
            for (t in inner.traces) QlogSchema.check(t.records)
        }

    /**
     * Peer bytes (field names and values, a PRIORITY_UPDATE's value) never end a record or break its JSON: quotes,
     * backslashes, control characters, the JSON-SEQ record separator and lone surrogates are escaped.
     */
    @Test fun negative_peerBytesNeverBreakARecord() {
        val recorded = ArrayList<String>()
        val q =
            H3Qlog(
                object : io.kuicksilver.quic.QlogRecorder {
                    override val enabled = true
                    override val logHeaderValues = true

                    override fun record(
                        name: String,
                        data: String,
                    ) {
                        recorded += "{\"time\":0.0,\"name\":\"$name\",\"data\":{$data}}"
                    }
                },
            )
        val nasty = "a\"b\\c\u0000\u001e\n\r\t\u007f\uD800z\uDC00\u2028}]"
        q.frameParsed(0, FrameType.HEADERS, 10, q.headers(listOf(nasty to nasty)))
        val prio = VarInt.encode(4) + nasty.encodeToByteArray()
        q.frameParsed(2, FrameType.PRIORITY_UPDATE_REQUEST, prio.size.toLong(), q.controlFrame(FrameType.PRIORITY_UPDATE_REQUEST, prio))
        q.frameParsed(2, FrameType.GOAWAY, 1, q.controlFrame(FrameType.GOAWAY, byteArrayOf(0x40))) // a truncated varint
        val header =
            "\u001e{\"qlog_format\":\"JSON-SEQ\",\"qlog_version\":\"0.3\"," +
                "\"trace\":{\"vantage_point\":{\"type\":\"server\"},\"common_fields\":{\"protocol_type\":[\"QUIC\",\"HTTP3\"]," +
                "\"time_format\":\"relative\",\"reference_time\":0.0}}}\n"
        val events = QlogSchema.check(listOf(header) + recorded.map { "\u001e$it\n" })
        val field = ((events[0]["data"] as Map<*, *>).frame()["headers"] as List<*>).single() as Map<*, *>
        assertEquals(nasty, field["name"])
        assertEquals(nasty, field["value"])
        assertEquals(nasty.encodeToByteArray().decodeToString(), (events[1]["data"] as Map<*, *>).frame()["priority_field_value"])
        assertEquals("unknown", (events[2]["data"] as Map<*, *>).frame()["frame_type"], "an unparsable GOAWAY is logged by its number")
    }

    /** The checker itself: a corrupt or off-schema record fails it. */
    @Test fun negative_theSchemaCheckRefusesWhatQvisWouldNot() {
        val header =
            "\u001e{\"qlog_format\":\"JSON-SEQ\",\"qlog_version\":\"0.3\"," +
                "\"trace\":{\"vantage_point\":{\"type\":\"client\"},\"common_fields\":{\"protocol_type\":[\"QUIC\",\"HTTP3\"]," +
                "\"time_format\":\"relative\",\"reference_time\":0.0}}}\n"
        val ok = "\u001e{\"time\":1.0,\"name\":\"http:frame_created\",\"data\":{\"stream_id\":0,\"frame\":{\"frame_type\":\"data\"}}}\n"
        QlogSchema.check(listOf(header, ok))
        val bad =
            listOf(
                ok.replace("}}}\n", "}}\n"), // truncated
                ok.replace("\"data\"}", "\"data\",}"), // trailing comma
                ok.replace("frame_created", "frame_made"), // an event the draft has not
                ok.replace("\"stream_id\":0,", ""), // a required member missing
                ok.replace("\"data\"}", "\"datum\"}"), // a frame type the draft has not
                ok.replace("\"stream_id\":0", "\"stream_id\":-1"), // not a uint
                ok.substring(1), // no RS
                ok + ok, // two records in one
                ok.replace("{\"frame_type\":\"data\"}", "{\"frame_type\":\"unknown\",\"raw_frame_type\":33}"), // h3-events-03's name
                ok.replace("{\"frame_type\":\"data\"}", "{\"frame_type\":\"reserved\",\"frame_type_value\":33}"), // 5.2.8 has none
            )
        for (b in bad) assertTrue(runCatching { QlogSchema.check(listOf(header, b)) }.isFailure, "accepted: $b")
        val badStream = "\u001e{\"time\":1.0,\"name\":\"http:stream_type_set\",\"data\":{\"stream_id\":2,\"new\":\"control\"}}\n"
        assertTrue(runCatching { QlogSchema.check(listOf(header, badStream)) }.isFailure, "section 4.3 names it stream_type")
        val later = ok.replace("\"time\":1.0", "\"time\":2.0")
        assertTrue(runCatching { QlogSchema.check(listOf(header, later, ok)) }.isFailure, "a time that goes back")
        for (h in listOf(header.replace(",\"HTTP3\"", ""), header.replace(",\"reference_time\":0.0", ""))) {
            assertTrue(runCatching { QlogSchema.check(listOf(h, ok)) }.isFailure, "accepted header: $h")
        }
    }
}
