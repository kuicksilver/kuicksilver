// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.request.uri
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeFully
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/**
 * What the server engine puts on the wire for an HTTP/2 call: the fields RFC 9110 asks of an origin server, content that
 * matches its length (RFC 9113 section 8.1.1), the stream's end in every case (a response, a reset, NO_ERROR after an
 * early response), and the connection-level limits and deadlines (REFUSED_STREAM, the send stall, the idle GOAWAY).
 */
class ServerH2ResponseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun client() =
        HttpClient(KuicksilverClient) {
            expectSuccess = false
            engine {
                trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
                http3 { discovery = Http3DiscoveryMode.H1Only }
            }
        }

    private val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")

    /** RFC 9110 section 6.6.1 (Date on 2xx to 4xx, the engine's own 425 included) and section 8.6 (no length on 204, 304). */
    @Test fun originFieldsAndFraming() =
        serverTest {
            val (server, port) =
                h2TlsServer {
                    routing {
                        get("/ok") { call.respondText("ok") }
                        get("/204") { call.respond(HttpStatusCode.NoContent) }
                        get("/304") { call.respond(HttpStatusCode.NotModified) }
                        get("/boom") { error("the handler failed") }
                        post("/early") { call.respondText("never") }
                    }
                }
            try {
                client().use { c ->
                    val base = "https://127.0.0.1:$port"
                    val ok = withTimeout(10.seconds) { c.get("$base/ok") }
                    assertEquals(HttpProtocolVersion.HTTP_2_0, ok.version)
                    assertNotNull(ok.headers["Date"])
                    val noContent = withTimeout(10.seconds) { c.get("$base/204") }
                    assertEquals(204, noContent.status.value)
                    assertNull(noContent.headers["Content-Length"])
                    val notModified = withTimeout(10.seconds) { c.get("$base/304") }
                    assertEquals(304, notModified.status.value)
                    assertNull(notModified.headers["Content-Length"])
                    val boom = withTimeout(10.seconds) { c.get("$base/boom") }
                    assertEquals(500, boom.status.value) // the handler's exception, answered as on HTTP/1.1
                    val early =
                        withTimeout(10.seconds) {
                            c.post("$base/early") {
                                header("Early-Data", "1")
                                setBody("x")
                            }
                        }
                    assertEquals(425, early.status.value) // RFC 8470 section 5.1
                    assertNotNull(early.headers["Date"])
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9113 section 8.1.1: a response never goes out with content that does not match its content-length. */
    @Test fun negative_contentNotMatchingItsLengthResetsTheStream() =
        serverTest {
            val (server, port) =
                h2TlsServer {
                    routing {
                        get("/short") { call.respondBytesWriter(contentLength = 10) { writeFully(ByteArray(3)) } }
                        get("/long") { call.respondBytesWriter(contentLength = 2) { writeFully(ByteArray(5)) } }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    for ((id, path) in listOf(1 to "/short", 3 to "/long")) {
                        raw.headers(id, RawH2Client.get(path))
                        val frames = ArrayList<RawFrame>()
                        withTimeout(10.seconds) {
                            while (true) {
                                val f = assertNotNull(raw.readFrame(), "$path: $frames")
                                frames += f
                                if (f.stream == id && (f.type == RawFrame.RST_STREAM || f.endStream)) break
                            }
                        }
                        val end = frames.last()
                        assertEquals(RawFrame.RST_STREAM, end.type, "$path: $frames")
                        assertEquals(0x2L, end.errorCode, path) // INTERNAL_ERROR
                        val sent = frames.filter { it.stream == id && it.type == RawFrame.DATA }.sumOf { it.payload.size }
                        assertTrue(sent <= if (path == "/long") 2 else 3, "$path: $sent bytes went out")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A call that ends without a response leaves no stream waiting: it is reset with INTERNAL_ERROR (RFC 9113 section 8.1). */
    @Test fun negative_callWithoutAResponseResetsItsStream() =
        serverTest {
            val (server, port) =
                h2TlsServer {
                    intercept(ApplicationCallPipeline.Plugins) { if (context.request.uri == "/none") finish() }
                    routing { get("/{...}") { call.respondText("ok") } }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get("/none"))
                    val f = assertNotNull(raw.await { it.stream == 1 && it.type != RawFrame.WINDOW_UPDATE })
                    assertEquals(RawFrame.RST_STREAM, f.type, "$f")
                    assertEquals(0x2L, f.errorCode)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9113 section 8.6: no 101, and a 1xx is never a final response: the application's one goes out as a 500. */
    @Test fun negative_finalInterimStatusIs500() =
        serverTest {
            val ended = CompletableDeferred<HttpStatusCode?>()
            val (server, port) =
                h2TlsServer(configure = {
                    eventListener =
                        object : KuicksilverServerEventListener() {
                            override fun requestEnded(
                                protocol: HttpProtocolVersion,
                                call: io.ktor.server.application.ApplicationCall,
                                cause: Throwable?,
                            ) {
                                ended.complete(call.response.status())
                            }
                        }
                }) { routing { get("/") { call.respond(HttpStatusCode.SwitchingProtocols) } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    val h = assertNotNull(raw.await { it.stream == 1 && it.type == RawFrame.HEADERS })
                    assertEquals(0x8e.toByte(), h.payload[0], ":status 500 (static index 14)")
                    assertTrue(h.endStream)
                }
                // the call says what was sent: listeners and logs see the 500, not the application's 1xx
                assertEquals(HttpStatusCode.InternalServerError, withTimeout(10.seconds) { ended.await() })
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9113 section 8.1: a response complete before the request is stopped with RST_STREAM NO_ERROR after it. */
    @Test fun earlyResponseStopsTheRequestWithNoError() =
        serverTest {
            val (server, port) = h2TlsServer { routing { post("/") { call.respondText("early") } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, post, endStream = false)
                    raw.data(1, "a".encodeToByteArray(), endStream = false)
                    val frames = ArrayList<RawFrame>()
                    withTimeout(10.seconds) {
                        while (true) {
                            val f = assertNotNull(raw.readFrame(), "$frames")
                            if (f.stream == 1) frames += f
                            if (f.stream == 1 && f.type == RawFrame.RST_STREAM) break
                        }
                    }
                    assertTrue(frames.any { it.type == RawFrame.DATA && it.endStream }, "the response is complete first: $frames")
                    assertEquals(0x0L, frames.last().errorCode)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9113 section 5.1.2: a stream above our SETTINGS_MAX_CONCURRENT_STREAMS is refused, the others go on. */
    @Test fun negative_streamAboveTheConcurrencyLimitIsRefused() =
        serverTest {
            val release = CompletableDeferred<Unit>()
            val started = CompletableDeferred<Unit>()
            val (server, port) =
                h2TlsServer(configure = { http2Settings = Http2Settings(maxConcurrentStreams = 1) }) {
                    routing {
                        get("/") {
                            started.complete(Unit)
                            release.await()
                            call.respondText("ok")
                        }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    withTimeout(10.seconds) { started.await() }
                    raw.headers(3, RawH2Client.get())
                    val refused = assertNotNull(raw.await { it.stream == 3 })
                    assertEquals(RawFrame.RST_STREAM, refused.type)
                    assertEquals(0x7L, refused.errorCode) // REFUSED_STREAM
                    release.complete(Unit)
                    assertNotNull(raw.await { it.stream == 1 && it.endStream })
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A client that grants no window: the response waits the send-stall deadline, then its stream is reset (CANCEL). */
    @Test fun negative_clientGrantingNoWindowGetsItsStreamReset() =
        serverTest {
            val (server, port) =
                h2TlsServer(configure = { sendStallTimeoutForTest = 1.seconds }) {
                    routing { get("/") { call.respondBytes(ByteArray(100_000)) } }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface(0x4 to 0L) // SETTINGS_INITIAL_WINDOW_SIZE = 0
                    raw.headers(1, RawH2Client.get())
                    val f = assertNotNull(raw.await(within = 15.seconds) { it.stream == 1 && it.type != RawFrame.HEADERS })
                    assertEquals(RawFrame.RST_STREAM, f.type, "$f")
                    assertEquals(0x8L, f.errorCode)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 9113 section 9.1: a connection without requests for the idle timeout gets GOAWAY (two steps) and closes. */
    @Test fun idleConnectionGetsGoAwayAndCloses() =
        serverTest {
            val (server, port) =
                h2TlsServer(configure = { connectionIdleTimeoutSeconds = 1 }) { routing { get("/") { call.respondText("ok") } } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    assertNotNull(raw.await { it.stream == 1 && it.endStream })
                    val first = assertNotNull(raw.await(within = 15.seconds) { it.type == RawFrame.GOAWAY })
                    assertEquals(Int.MAX_VALUE, first.lastStreamId)
                    val ping = assertNotNull(raw.await { it.type == RawFrame.PING && it.flags and 1 == 0 })
                    raw.write(RawH2Client.frame(RawFrame.PING, 1, 0, ping.payload))
                    val rest = raw.readToEnd()
                    val last = assertNotNull(rest.lastOrNull { it.type == RawFrame.GOAWAY }, "$rest")
                    assertEquals(1, last.lastStreamId)
                    assertEquals(0L, last.errorCode)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Ktor's connection point describes the connection: `https` whatever the request's `:scheme` (RFC 9113 section 8.3.1
     * allows other schemes there; the request did arrive over TLS).
     */
    @Test fun connectionPointSchemeIsTheConnections() =
        serverTest {
            val schemes = Channel<String>(Channel.UNLIMITED)
            val (server, port) =
                h2TlsServer {
                    routing {
                        get("/") {
                            schemes.trySend(call.request.local.scheme)
                            call.respondText("ok")
                        }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get().map { if (it.first == ":scheme") ":scheme" to "http" else it })
                    assertEquals("https", withTimeout(10.seconds) { schemes.receive() })
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
