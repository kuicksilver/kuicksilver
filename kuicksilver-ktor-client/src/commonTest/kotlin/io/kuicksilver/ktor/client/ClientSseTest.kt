// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.sse.SSE
import io.ktor.client.plugins.sse.serverSentEventsSession
import io.ktor.client.plugins.sse.sse
import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.request.preparePost
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.install
import io.ktor.server.request.httpVersion
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.sse.ServerSentEvent
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource
import io.ktor.server.sse.SSE as ServerSSE
import io.ktor.server.sse.sse as serverSse

/**
 * Ktor's SSE plugin, and other bodies read after the call's own work returned, over each protocol. Ktor hands a
 * `text/event-stream` body to the SSE session and then ends the call (`HttpStatement.cleanup`: the call's job completes
 * and is joined): the session reads the body later. The engine keeps the response's stream for as long as that body is
 * read, as Ktor's engines keep theirs (a child of the call's job): before, the HTTP/2 and HTTP/3 streams were released
 * as soon as the call's job completed, and the session saw an empty, ended stream (no events, no error).
 */
class ClientSseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private enum class Proto { H1, H2, H3 }

    /** A Kuicksilver server engine with [module] over [p]; the client to it; the URL base. */
    private suspend fun withServer(
        p: Proto,
        module: io.ktor.server.application.Application.() -> Unit,
        block: suspend (client: HttpClient, base: String) -> Unit,
    ) {
        val (server, port) = testServer(configure = { if (p == Proto.H2) http2 { enabled = true } }, module = module)
        try {
            testClient(if (p == Proto.H3) Http3Discovery.H3Only else null, block = { install(SSE) }).use { c ->
                block(c, "https://127.0.0.1:$port")
            }
        } finally {
            server.stop(100, 500)
        }
    }

    private fun Proto.version() =
        when (this) {
            Proto.H1 -> HttpProtocolVersion.HTTP_1_1
            Proto.H2 -> HttpProtocolVersion.HTTP_2_0
            Proto.H3 -> HttpProtocolVersion.HTTP_3_0
        }

    private fun Proto.run(block: suspend () -> Unit) = if (this == Proto.H3) h3Test(block) else clientTest(block)

    // ---- every event, in order, across pauses ----

    private fun everyEventAcrossPauses(p: Proto) =
        p.run {
            withServer(p, {
                install(ServerSSE)
                routing {
                    serverSse("/events") {
                        for (i in 1..5) {
                            send(ServerSentEvent("e$i", id = "$i"))
                            // a long pause once: the stream stays open while nothing comes
                            delay(if (i == 3) 1000 else 150)
                        }
                    }
                }
            }) { c, base ->
                val got = ArrayList<String>()
                val start = TimeSource.Monotonic.markNow()
                var version: HttpProtocolVersion? = null
                c.sse("$base/events") {
                    version = call.response.version
                    incoming.collect { e -> e.data?.let { got += it } }
                }
                assertEquals(p.version(), version)
                assertEquals(listOf("e1", "e2", "e3", "e4", "e5"), got)
                assertTrue(start.elapsedNow() >= 1.seconds, "the session lasted across the pauses: ${start.elapsedNow()}")
                // the client goes on: the stream (and the connection) was given back in order
                assertEquals(p.version(), c.get("$base/events").version)
            }
        }

    @Test fun everyEventAcrossPausesOverH1() = everyEventAcrossPauses(Proto.H1)

    @Test fun everyEventAcrossPausesOverH2() = everyEventAcrossPauses(Proto.H2)

    @Test fun everyEventAcrossPausesOverH3() = everyEventAcrossPauses(Proto.H3)

    /** A session collected late (`serverSentEventsSession()`, then a pause): what came meanwhile is read, then the rest. */
    private fun sessionCollectedLate(p: Proto) =
        p.run {
            withServer(p, {
                install(ServerSSE)
                routing {
                    serverSse("/events") {
                        send(ServerSentEvent("a"))
                        send(ServerSentEvent("b"))
                        delay(800)
                        send(ServerSentEvent("c"))
                    }
                }
            }) { c, base ->
                val session = c.serverSentEventsSession("$base/events")
                delay(500)
                val got = ArrayList<String>()
                session.incoming.collect { e -> e.data?.let { got += it } }
                assertEquals(listOf("a", "b", "c"), got)
            }
        }

    @Test fun sessionCollectedLateOverH1() = sessionCollectedLate(Proto.H1)

    @Test fun sessionCollectedLateOverH2() = sessionCollectedLate(Proto.H2)

    @Test fun sessionCollectedLateOverH3() = sessionCollectedLate(Proto.H3)

    // ---- the client leaves: the server's handler ends ----

    /**
     * The client leaves an endless event stream, by ending its block ([cancelCaller] false) or with its coroutine cancelled:
     * the server sees it go (its handler's send fails) and the client goes on.
     */
    private fun serverSeesTheClientLeave(
        p: Proto,
        cancelCaller: Boolean,
    ) = p.run {
        val ended = CompletableDeferred<Unit>()
        withServer(p, {
            install(ServerSSE)
            routing {
                serverSse("/events") {
                    try {
                        var i = 0
                        while (true) {
                            send(ServerSentEvent("e${i++}"))
                            delay(100)
                        }
                    } finally {
                        ended.complete(Unit)
                    }
                }
                get("/") { call.respondText("ok") }
            }
        }) { c, base ->
            val got = ArrayList<String>()
            if (cancelCaller) {
                coroutineScope {
                    val two = CompletableDeferred<Unit>()
                    val job =
                        launch {
                            c.sse("$base/events") {
                                incoming.collect { e ->
                                    got += e.data!!
                                    if (got.size == 2) two.complete(Unit)
                                }
                            }
                        }
                    withTimeout(10.seconds) { two.await() }
                    job.cancelAndJoin()
                }
            } else {
                c.sse("$base/events") { incoming.take(2).collect { e -> got += e.data!! } }
            }
            assertEquals(listOf("e0", "e1"), got.take(2))
            withTimeout(10.seconds) { ended.await() }
            assertEquals("ok", c.get("$base/").bodyAsText())
        }
    }

    @Test fun serverSeesTheClientLeaveOverH1() = serverSeesTheClientLeave(Proto.H1, cancelCaller = false)

    @Test fun serverSeesTheClientLeaveOverH2() = serverSeesTheClientLeave(Proto.H2, cancelCaller = false)

    @Test fun serverSeesTheClientLeaveOverH3() = serverSeesTheClientLeave(Proto.H3, cancelCaller = false)

    @Test fun serverSeesACancelledCallerLeaveOverH1() = serverSeesTheClientLeave(Proto.H1, cancelCaller = true)

    @Test fun serverSeesACancelledCallerLeaveOverH2() = serverSeesTheClientLeave(Proto.H2, cancelCaller = true)

    @Test fun serverSeesACancelledCallerLeaveOverH3() = serverSeesTheClientLeave(Proto.H3, cancelCaller = true)

    // ---- HTTP/2: the stream is reset with CANCEL (RFC 9113 section 8.1) ----

    /** An endless event stream on the raw HTTP/2 server: each stream's reset code goes to [resets]. */
    private suspend fun h2EventServer(
        resets: Channel<Http2ErrorCode?>,
        maxConcurrentStreams: Int = 100,
        block: suspend (port: Int, log: H2ServerLog) -> Unit,
    ) = tlsH2WithSilentUdp(
        settings = http2Settings { this.maxConcurrentStreams = maxConcurrentStreams.toLong() },
        onRequest = { _, r ->
            r.respond(200, listOf("content-type" to "text/event-stream"))
            val source = ByteChannel()
            val writer =
                launch {
                    var i = 0
                    while (true) {
                        source.writeStringUtf8("data: e${i++}\n\n")
                        source.flush()
                        delay(100)
                    }
                }
            try {
                val e = runCatching { r.sendBody(source) }.exceptionOrNull()
                resets.send((e as? Http2Exception.StreamReset)?.code)
            } finally {
                writer.cancel()
            }
        },
        block = block,
    )

    private fun h2Client() = testClient(block = { install(SSE) })

    /** The session's block ends after two events: the stream is reset with CANCEL, once. */
    @Test fun h2SessionEndResetsTheStreamWithCancel() =
        clientTest {
            val resets = Channel<Http2ErrorCode?>(Channel.UNLIMITED)
            h2EventServer(resets) { port, _ ->
                h2Client().use { c ->
                    val got = ArrayList<String>()
                    c.sse("https://127.0.0.1:$port/") { incoming.take(2).collect { got += it.data!! } }
                    assertEquals(listOf("e0", "e1"), got)
                    assertEquals(Http2ErrorCode.CANCEL, withTimeout(10.seconds) { resets.receive() })
                }
            }
        }

    /** The caller's coroutine is cancelled while the session waits for the next event: the stream is reset with CANCEL. */
    @Test fun h2CancelledCallerResetsTheStreamWithCancel() =
        clientTest {
            val resets = Channel<Http2ErrorCode?>(Channel.UNLIMITED)
            h2EventServer(resets) { port, _ ->
                h2Client().use { c ->
                    coroutineScope {
                        val first = CompletableDeferred<Unit>()
                        val job =
                            launch {
                                c.sse("https://127.0.0.1:$port/") { incoming.collect { first.complete(Unit) } }
                            }
                        withTimeout(10.seconds) { first.await() }
                        job.cancelAndJoin()
                    }
                    assertEquals(Http2ErrorCode.CANCEL, withTimeout(10.seconds) { resets.receive() })
                }
            }
        }

    /** A session that is never collected, only cancelled: its stream is reset with CANCEL, nothing waits for it. */
    @Test fun h2SessionCancelledUncollectedResetsTheStream() =
        clientTest {
            val resets = Channel<Http2ErrorCode?>(Channel.UNLIMITED)
            h2EventServer(resets) { port, _ ->
                h2Client().use { c ->
                    val session = c.serverSentEventsSession("https://127.0.0.1:$port/")
                    delay(300)
                    session.coroutineContext[Job]!!.cancel()
                    assertEquals(Http2ErrorCode.CANCEL, withTimeout(10.seconds) { resets.receive() })
                }
            }
        }

    /**
     * Sessions one after the other on a server that allows one stream at a time: each ended session gave its stream back,
     * so all of them, and plain calls between them, go on the first connection (a stream still held would make the client
     * open another).
     */
    @Test fun h2SessionsInARowGiveTheirStreamsBack() =
        clientTest {
            val resets = Channel<Http2ErrorCode?>(Channel.UNLIMITED)
            h2EventServer(resets, maxConcurrentStreams = 1) { port, log ->
                h2Client().use { c ->
                    repeat(6) { i ->
                        val got = ArrayList<String>()
                        c.sse("https://127.0.0.1:$port/") { incoming.take(1 + i % 2).collect { got += it.data!! } }
                        assertEquals(1 + i % 2, got.size)
                        assertEquals(Http2ErrorCode.CANCEL, withTimeout(10.seconds) { resets.receive() })
                    }
                    assertEquals(1, log.acceptCount)
                }
            }
        }

    // ---- HTTP/3: STOP_SENDING with H3_REQUEST_CANCELLED (RFC 9114 section 4.1.1) ----

    /** The client's STOP_SENDING and RESET_STREAM frames on its request streams, from its qlog: "type stream code". */
    private class StopsSent : QlogSink {
        val frames = MutableStateFlow<List<String>>(emptyList())

        /**
         * The client's recovery in the order it happened: "sent <frame> @ <packet>" for each frame of [frames], "lost
         * <packet>" for each `recovery:packet_lost`, "pto" for each `recovery:metrics_updated` with a probe timeout running.
         */
        private val log = MutableStateFlow<List<String>>(emptyList())

        /**
         * Whether every frame sent more than once was sent again only by loss recovery (RFC 9002 section 6): for each copy
         * after the first, the packet that carried the copy before it was declared lost, or a probe timeout ran between that
         * copy and the one after this (a probe packet carries the frames of the oldest unacknowledged packets, section
         * 6.2.4, and the client logs the probe timeout's metrics after it sent the probe). A second abandon of the stream by
         * the client, with no recovery around it, fails it.
         */
        fun repeatsOnlyAfterLoss(): Boolean {
            val entries = log.value
            val lostPackets = entries.filter { it.startsWith("lost ") }.map { it.removePrefix("lost ") }.toSet()
            val ptos = entries.indices.filter { entries[it] == "pto" }
            val copies = HashMap<String, MutableList<Pair<Int, String>>>() // frame -> (index in the log, packet) of each copy
            for ((i, e) in entries.withIndex()) {
                if (!e.startsWith("sent ")) continue
                val (frame, packet) = e.removePrefix("sent ").split(" @ ")
                copies.getOrPut(frame) { ArrayList() } += i to packet
            }
            return copies.values.all { c ->
                (1 until c.size).all { k ->
                    val (before, packet) = c[k - 1]
                    val until = if (k + 1 < c.size) c[k + 1].first else entries.size
                    packet in lostPackets || ptos.any { it in (before + 1) until until }
                }
            }
        }

        /** [log], for a failure message. */
        val recovery: List<String> get() = log.value

        override fun open(
            odcidHex: String,
            role: TlsRole,
        ): QlogTrace =
            object : QlogTrace {
                override fun write(record: String) {
                    val packet = PACKET.find(record)?.destructured?.let { (t, n) -> "$t $n" } ?: "?"
                    if ("recovery:packet_lost" in record) {
                        log.update { it + "lost $packet" }
                    } else if ("recovery:metrics_updated" in record && PTO.containsMatchIn(record)) {
                        log.update { it + "pto" }
                    } else if ("packet_sent" in record) {
                        for (m in STOP_OR_RESET.findAll(record)) {
                            val (type, stream, code) = m.destructured
                            // client-initiated bidirectional streams only (RFC 9000 section 2.1)
                            if (stream.toLong() % 4 == 0L) {
                                frames.update { it + "$type $stream $code" }
                                log.update { it + "sent $type $stream $code @ $packet" }
                            }
                        }
                    }
                }

                override fun close() {}
            }
    }

    /** An endless event stream on a raw HTTP/3 server; ends when [block] returns. */
    private suspend fun h3EventServer(block: suspend (port: Int) -> Unit) =
        coroutineScope {
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            server =
                                QuicServerConfig
                                    .Builder(
                                        tlsConfig(TlsRole.Server) {
                                            alpn = listOf(Http3Endpoint.H3)
                                            identity = ClientFixtures.identity()
                                        },
                                    ).build()
                        }.build(),
                )
            val serving =
                launch {
                    val conn = ep.accept()
                    while (true) {
                        val r = runCatching { conn.acceptRequest() }.getOrNull() ?: break
                        launch {
                            runCatching {
                                val w = r.respond(200, Http3Headers.of("content-type" to "text/event-stream"))
                                var i = 0
                                while (true) {
                                    w.output.writeStringUtf8("data: e${i++}\n\n")
                                    w.output.flush()
                                    delay(100)
                                }
                            }
                        }
                    }
                }
            try {
                block(ep.localAddress.port)
            } finally {
                serving.cancel()
                ep.close()
            }
        }

    private fun h3StopSendingCancelled(cancelCaller: Boolean) =
        h3Test {
            h3EventServer { port ->
                val sent = StopsSent()
                val c = testClient(Http3Discovery.H3Only, engine = { observability { qlog = sent } }, block = { install(SSE) })
                try {
                    val url = "https://127.0.0.1:$port/"
                    if (cancelCaller) {
                        coroutineScope {
                            val first = CompletableDeferred<Unit>()
                            val job = launch { c.sse(url) { incoming.collect { first.complete(Unit) } } }
                            withTimeout(10.seconds) { first.await() }
                            job.cancelAndJoin()
                        }
                    } else {
                        val got = ArrayList<String>()
                        c.sse(url) { incoming.take(2).collect { got += it.data!! } }
                        assertEquals(listOf("e0", "e1"), got)
                    }
                    // H3_REQUEST_CANCELLED is 0x010c (RFC 9114 section 8.1): sent when the session ended, not at the close
                    withTimeout(10.seconds) { sent.frames.first { f -> f.any { it.startsWith("stop_sending ") } } }
                } finally {
                    c.close()
                }
                withTimeout(10.seconds) { (c.engine as KuicksilverEngine).cleanup.join() }
                // once: the session's end and the call's end abandon the stream together, and the close adds nothing (the
                // GET's FIN went out with its head, so there is no send half to reset)
                val frames = sent.frames.value
                assertEquals(setOf("stop_sending 0 268"), frames.toSet(), "$frames")
                // a frame sent again is loss recovery (a lost packet, a probe), never a second abandon
                assertTrue(sent.repeatsOnlyAfterLoss(), "once: ${sent.recovery}")
            }
        }

    @Test fun h3SessionEndStopsTheStreamWithRequestCancelled() = h3StopSendingCancelled(cancelCaller = false)

    @Test fun h3CancelledCallerStopsTheStreamWithRequestCancelled() = h3StopSendingCancelled(cancelCaller = true)

    /**
     * An alternative's 421 is dropped by the engine, which sends the request again over TCP. Its HTTP/3 stream is abandoned
     * at once, while the call goes on with the repeat, not at the call's end, and once (the client's close included): STOP_SENDING
     * for the response the server is still sending and RESET_STREAM for the upload still going, both H3_REQUEST_CANCELLED
     * (RFC 9114 section 4.1.1). A 421 that arrived whole needs no STOP_SENDING (RFC 9000 section 3.5).
     */
    @Test fun h3AlternativesMisdirectedResponseIsAbandonedAtOnce() =
        h3Test {
            val misdirected = MutableStateFlow(0) // written by the server, read by the test
            val release = CompletableDeferred<Unit>()
            val (server, port) =
                testServer {
                    routing {
                        post("/m") {
                            if (call.request.httpVersion == "HTTP/3") {
                                misdirected.value++
                                // answers without reading the upload, and keeps its response open
                                call.respondBytesWriter(status = HttpStatusCode.fromValue(421)) {
                                    writeStringUtf8("elsewhere")
                                    flush()
                                    release.await()
                                }
                            } else {
                                call.receiveText()
                                call.respondText("ok")
                            }
                        }
                    }
                }
            try {
                val sent = StopsSent()
                val c = testClient(Http3Discovery.Auto, engine = { observability { qlog = sent } })
                try {
                    // the first request learns Alt-Svc over HTTP/1.1; requests go on until one reaches the alternative
                    // (as ClientPriorityTest.updatePriorityAfter421FallbackIsFalse). The upload (bytes: it can go again)
                    // outgrows the stream's flow-control window, so it is still being sent when the 421 comes
                    withTimeout(10.seconds) {
                        while (misdirected.value == 0) {
                            c.preparePost("https://127.0.0.1:$port/m") { setBody(ByteArray(8 shl 20)) }.execute { r ->
                                assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                                assertEquals("ok", r.bodyAsText())
                                // the repeat's call is still going: the 421's stream was abandoned already
                                if (misdirected.value > 0) {
                                    sent.frames.first { f ->
                                        f.any { it.startsWith("stop_sending ") } && f.any { it.startsWith("reset_stream ") }
                                    }
                                }
                            }
                        }
                    }
                } finally {
                    c.close()
                    release.complete(Unit)
                }
                withTimeout(10.seconds) { (c.engine as KuicksilverEngine).cleanup.join() }
                val frames = sent.frames.value
                val streams = frames.map { it.split(' ')[1] }.distinct()
                assertEquals(1, streams.size, "$frames")
                val id = streams.single()
                assertEquals(setOf("stop_sending $id 268", "reset_stream $id 268"), frames.toSet(), "$frames")
                // once each: a frame sent again is loss recovery (the macOS loopback drops datagrams under the upload: a
                // lost packet, a probe), never a second abandon
                assertTrue(sent.repeatsOnlyAfterLoss(), "once each: ${sent.recovery}")
            } finally {
                release.complete(Unit)
                server.stop(100, 500)
            }
        }

    // ---- other bodies read past the call's own work ----

    /** A streamed body read slowly across the server's pauses, inside `execute { }`: every byte, over each protocol. */
    private fun slowConsumer(p: Proto) =
        p.run {
            withServer(p, {
                routing {
                    get("/slow") {
                        call.respondBytesWriter {
                            for (i in 0 until 6) {
                                writeStringUtf8("chunk$i;")
                                flush()
                                delay(200)
                            }
                        }
                    }
                }
            }) { c, base ->
                val text =
                    c.prepareGet("$base/slow").execute { r ->
                        assertEquals(p.version(), r.version)
                        val ch = r.bodyAsChannel()
                        val out = StringBuilder()
                        val buf = ByteArray(5)
                        while (true) {
                            val n = ch.readAvailable(buf, 0, buf.size)
                            if (n < 0) break
                            out.append(buf.decodeToString(0, n))
                            delay(50) // slower than the server
                        }
                        out.toString()
                    }
                assertEquals((0 until 6).joinToString("") { "chunk$it;" }, text)
            }
        }

    @Test fun slowConsumerOverH1() = slowConsumer(Proto.H1)

    @Test fun slowConsumerOverH2() = slowConsumer(Proto.H2)

    @Test fun slowConsumerOverH3() = slowConsumer(Proto.H3)

    /**
     * A session cancelled from outside while its incoming flow is collected elsewhere: the collector ends, and so does the
     * server's handler, over each protocol.
     */
    private fun sessionCancelledWhileCollected(p: Proto) =
        p.run {
            val ended = CompletableDeferred<Unit>()
            withServer(p, {
                install(ServerSSE)
                routing {
                    serverSse("/events") {
                        try {
                            while (true) {
                                send(ServerSentEvent("x"))
                                delay(100)
                            }
                        } finally {
                            ended.complete(Unit)
                        }
                    }
                }
            }) { c, base ->
                val session = c.serverSentEventsSession("$base/events")
                val collected = CompletableDeferred<Unit>()
                coroutineScope {
                    val reader =
                        launch(start = CoroutineStart.UNDISPATCHED) {
                            runCatching { session.incoming.collect { collected.complete(Unit) } }
                        }
                    withTimeout(10.seconds) { collected.await() }
                    session.coroutineContext[Job]!!.cancel()
                    withTimeout(10.seconds) { reader.join() }
                }
                withTimeout(10.seconds) { ended.await() }
            }
        }

    @Test fun sessionCancelledWhileCollectedOverH1() = sessionCancelledWhileCollected(Proto.H1)

    @Test fun sessionCancelledWhileCollectedOverH2() = sessionCancelledWhileCollected(Proto.H2)

    @Test fun sessionCancelledWhileCollectedOverH3() = sessionCancelledWhileCollected(Proto.H3)

    /**
     * The client is closed while a session is collected: as every call in flight, the session goes on until it is closed
     * (docs/guide/client.md, "Closing the client"), over each protocol alike; then the engine's cleanup runs and the server's
     * handler ends.
     */
    private fun clientClosedUnderASession(p: Proto) =
        p.run {
            val ended = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(configure = { if (p == Proto.H2) http2 { enabled = true } }) {
                    install(ServerSSE)
                    routing {
                        serverSse("/events") {
                            try {
                                while (true) {
                                    send(ServerSentEvent("x"))
                                    delay(100)
                                }
                            } finally {
                                ended.complete(Unit)
                            }
                        }
                    }
                }
            try {
                val c = testClient(if (p == Proto.H3) Http3Discovery.H3Only else null, block = { install(SSE) })
                val engine = c.engine as KuicksilverEngine
                coroutineScope {
                    val events = Channel<Unit>(Channel.UNLIMITED)
                    val reader =
                        launch {
                            runCatching {
                                c.sse("https://127.0.0.1:$port/events") { incoming.collect { events.send(Unit) } }
                            }
                        }
                    withTimeout(10.seconds) { events.receive() }
                    c.close()
                    // the session still gets events after the close, and the cleanup waits for it
                    repeat(3) { withTimeout(10.seconds) { events.receive() } }
                    assertTrue(!engine.cleanup.isCompleted && !ended.isCompleted)
                    reader.cancelAndJoin()
                    withTimeout(10.seconds) { engine.cleanup.join() }
                }
                withTimeout(10.seconds) { ended.await() }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun clientClosedUnderASessionOverH1() = clientClosedUnderASession(Proto.H1)

    @Test fun clientClosedUnderASessionOverH2() = clientClosedUnderASession(Proto.H2)

    @Test fun clientClosedUnderASessionOverH3() = clientClosedUnderASession(Proto.H3)

    // ---- a known Ktor issue: a session whose caller was cancelled before the response head ----

    /**
     * KNOWN KTOR ISSUE (Ktor 3.6.1, every engine): `serverSentEventsSession()` runs the request in a coroutine of the client's
     * own scope (`processSession`) and hands the session over through a deferred whose `complete` result it ignores. A
     * caller cancelled before the response head no longer waits for it, but the request goes on: the session made from the
     * response is handed to nobody, nothing reads or closes it, and it holds its call (the HTTP/1.1 body writer, the HTTP/2
     * or HTTP/3 stream), so the server streams on and the client's close waits for it. The engine cannot tell: Ktor gives it
     * no signal that the session was dropped. Only cancelling the call's job ends it (done here at the end, through a
     * plugin that saw the response). This test records that behaviour, the same over every protocol; it fails once Ktor
     * ends such a session itself: then the guide (realtime.md, "Server-sent events") and this test change.
     */
    private fun orphanedSessionHoldsItsCall(p: Proto) =
        p.run {
            val requested = CompletableDeferred<Unit>()
            val gate = CompletableDeferred<Unit>()
            val closed = MutableStateFlow(false)
            val sentAfterClose = Channel<Unit>(Channel.UNLIMITED)
            val handlerEnded = CompletableDeferred<Unit>()
            val (server, port) =
                testServer(configure = { if (p == Proto.H2) http2 { enabled = true } }) {
                    routing {
                        get("/events") {
                            requested.complete(Unit)
                            gate.await()
                            try {
                                call.respondBytesWriter(contentType = ContentType.Text.EventStream) {
                                    var i = 0
                                    while (true) {
                                        writeStringUtf8("data: e${i++}\n\n")
                                        flush()
                                        if (closed.value) sentAfterClose.send(Unit)
                                        delay(50)
                                    }
                                }
                            } finally {
                                handlerEnded.complete(Unit)
                            }
                        }
                    }
                }
            try {
                val calls = MutableStateFlow<List<Job>>(emptyList())
                val c =
                    testClient(if (p == Proto.H3) Http3Discovery.H3Only else null, block = {
                        install(SSE)
                        install(
                            createClientPlugin("SeenCalls") {
                                onResponse { r -> calls.update { it + r.coroutineContext[Job]!! } }
                            },
                        )
                    })
                val engine = c.engine as KuicksilverEngine
                try {
                    coroutineScope {
                        val caller = launch { c.serverSentEventsSession("https://127.0.0.1:$port/events") }
                        withTimeout(10.seconds) { requested.await() }
                        caller.cancelAndJoin() // before the response head
                        gate.complete(Unit)
                    }
                    withTimeout(10.seconds) { calls.first { it.isNotEmpty() } } // Ktor made the session all the same
                    c.close()
                    closed.value = true
                    // the server streams on after the close (five more events) rather than seeing the client go
                    val held =
                        withTimeout(10.seconds) {
                            coroutineScope {
                                val more = async { repeat(5) { sentAfterClose.receive() } }
                                val ended = async { handlerEnded.await() }
                                select {
                                    more.onAwait { true }
                                    ended.onAwait { false }
                                }.also {
                                    more.cancel()
                                    ended.cancel()
                                }
                            }
                        }
                    assertTrue(held, "Ktor now ends a session whose caller left: update realtime.md and this test")
                    assertTrue(!engine.cleanup.isCompleted, "the close waits for the orphaned session")
                } finally {
                    // the only way out: the call's job
                    for (j in calls.value) j.cancel()
                    c.close()
                }
                withTimeout(10.seconds) { engine.cleanup.join() }
                withTimeout(10.seconds) { handlerEnded.await() }
            } finally {
                gate.complete(Unit)
                server.stop(100, 500)
            }
        }

    @Test fun knownKtorIssue_anOrphanedSessionHoldsItsCallOverH1() = orphanedSessionHoldsItsCall(Proto.H1)

    @Test fun knownKtorIssue_anOrphanedSessionHoldsItsCallOverH2() = orphanedSessionHoldsItsCall(Proto.H2)

    @Test fun knownKtorIssue_anOrphanedSessionHoldsItsCallOverH3() = orphanedSessionHoldsItsCall(Proto.H3)

    private companion object {
        val PTO = Regex("\"pto_count\":[1-9]")
        val PACKET = Regex("\"packet_type\":\"([^\"]+)\",\"packet_number\":(\\d+)")
        val STOP_OR_RESET =
            Regex("\"frame_type\":\"(reset_stream|reset_stream_at|stop_sending)\",\"stream_id\":(\\d+),\"error_code\":(\\d+)")
    }
}
