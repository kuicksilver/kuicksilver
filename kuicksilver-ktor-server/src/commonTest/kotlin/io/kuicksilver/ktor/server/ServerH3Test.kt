// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.request.httpVersion
import io.ktor.server.request.receive
import io.ktor.server.response.header
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal suspend fun ByteReadChannel.readFullBody(): ByteArray {
    val out = kotlinx.io.Buffer()
    val b = ByteArray(16384)
    while (true) {
        val n = readAvailable(b, 0, b.size)
        if (n <
            0
        ) {
            break
        }
        out.write(b, 0, n)
    }
    closedCause?.let { throw it }
    return out.readByteArray()
}

/** HTTP/3 on the TLS connector's port, checked with the kuicksilver-http3 client. */
@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
class ServerH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

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

    private fun get(path: String = "/") = http3Request("GET", "server.test", path)

    @Test fun getOverH3() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get(
                            "/",
                        ) {
                            call.respondText(
                                "${call.request.httpVersion} ${call.request.local.scheme} ${call.request.local.method.value}",
                            )
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val r = c.request(get())
                    assertEquals(200, r.status)
                    assertEquals("HTTP/3 https GET", r.body.readFullBody().decodeToString())
                    assertTrue(r.headers["content-type"]!!.startsWith("text/plain"))
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun postEchoLargeBody() =
        h3ServerTest {
            val payload = ByteArray(4 shl 20) { (it * 31).toByte() }
            val (server, port) = tlsServer { routing { post("/echo") { call.respondBytes(call.receive<ByteArray>()) } } }
            try {
                h3(port) { c ->
                    val r =
                        c.request(
                            http3Request("POST", "server.test", "/echo") {
                                body = ByteReadChannel(payload)
                            },
                        )
                    assertContentEquals(payload, r.body.readFullBody())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9110 section 10.1.1 over HTTP/3: `Expect: 100-continue` with content gets an immediate interim 100 as the handler
     * starts, before it reads or answers. Before, HTTP/3 never sent it: the client held its content back until its own wait
     * ended.
     */
    @Test fun expectContinueGets100BeforeTheHandlerReads() =
        h3ServerTest {
            val answer = CompletableDeferred<Unit>()
            val (server, port) =
                tlsServer {
                    routing {
                        post("/deny") {
                            answer.await()
                            call.respondText("no", status = io.ktor.http.HttpStatusCode.Forbidden)
                        }
                    }
                }
            try {
                h3(port) { c ->
                    coroutineScope {
                        val interim = CompletableDeferred<Int>()
                        val content =
                            io.ktor.utils.io
                                .ByteChannel(autoFlush = true)
                        val response =
                            async {
                                c.request(
                                    http3Request("POST", "server.test", "/deny") {
                                        headers =
                                            io.kuicksilver.http3.Http3Headers
                                                .of("expect" to "100-continue", "content-length" to "2")
                                        body = content
                                        onInformational = { status, _ -> interim.complete(status) }
                                    },
                                )
                            }
                        assertEquals(100, kotlinx.coroutines.withTimeout(10.seconds) { interim.await() })
                        assertTrue(!answer.isCompleted, "the interim 100 before the handler answered")
                        content.writeFully("hi".encodeToByteArray())
                        content.flushAndClose()
                        answer.complete(Unit)
                        assertEquals(403, kotlinx.coroutines.withTimeout(10.seconds) { response.await() }.status)
                    }
                }
            } finally {
                answer.complete(Unit)
                server.stop(100, 500)
            }
        }

    @Test fun unknownLengthBodyOverH3HasNoTransferEncoding() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get(
                            "/",
                        ) { call.respondBytesWriter { repeat(100) { writeFully(ByteArray(30_000) { 7 }) } } }
                    }
                }
            try {
                h3(port) { c ->
                    val r = c.request(get())
                    assertNull(r.headers["transfer-encoding"])
                    assertNull(r.headers["connection"])
                    assertEquals(3_000_000, r.body.readFullBody().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** `te` is a request-only field (RFC 9110 section 10.1.4): the engine drops it from an HTTP/3 response like the other hop-by-hop fields. */
    @Test fun teStrippedFromH3Response() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("TE", "trailers")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val r = c.request(get())
                    assertEquals(200, r.status)
                    assertNull(r.headers["te"])
                    assertEquals("ok", r.body.readFullBody().decodeToString())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9110 section 10.1.1: `Expect: 100-continue` gets an interim 100 once the application reads the body, and the
     * client, which holds its content until then, completes; another expectation is answered 417.
     */
    @Test fun expectContinueGetsAnInterim100() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { post("/") { call.respondText(call.receive<String>()) } } }
            try {
                h3(port) { c ->
                    val body =
                        io.ktor.utils.io
                            .ByteChannel()
                    val interim = ArrayList<Int>()
                    val r =
                        kotlinx.coroutines.withTimeout(10.seconds) {
                            c.request(
                                http3Request("POST", "server.test", "/") {
                                    headers =
                                        io.kuicksilver.http3.Http3Headers
                                            .of("expect" to "100-continue", "content-length" to "2")
                                    this.body = body
                                    onInformational = { status, _ ->
                                        interim += status
                                        // the content goes only after the 100
                                        body.writeFully("hi".encodeToByteArray())
                                        body.flushAndClose()
                                    }
                                },
                            )
                        }
                    assertEquals(listOf(100), interim)
                    assertEquals(200, r.status)
                    assertEquals("hi", r.body.readFullBody().decodeToString())
                    val other =
                        c.request(
                            http3Request("POST", "server.test", "/") {
                                headers =
                                    io.kuicksilver.http3.Http3Headers
                                        .of("expect" to "something-else", "content-length" to "2")
                                this.body = ByteReadChannel("hi")
                            },
                        )
                    assertEquals(417, other.status)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** HEAD, 204 and 304 carry no content (RFC 9110 sections 9.3.2, 15.3.5, 15.4.5): no DATA frame leaves the server, HEAD keeps content-length. */
    @Test fun headAnd204And304SendNoData() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        route("/h", io.ktor.http.HttpMethod.Head) { handle { call.respondText("body") } }
                        get("/204") { call.respondText("body", status = io.ktor.http.HttpStatusCode.NoContent) }
                        get("/304") { call.respondText("body", status = io.ktor.http.HttpStatusCode.NotModified) }
                    }
                }
            try {
                h3(port) { c ->
                    val head = c.request(http3Request("HEAD", "server.test", "/h"))
                    assertEquals(200, head.status)
                    assertEquals("4", head.headers["content-length"])
                    assertEquals(0, head.body.readFullBody().size)
                    for (status in listOf(204, 304)) {
                        val r = c.request(get("/$status"))
                        assertEquals(status, r.status)
                        assertEquals(0, r.body.readFullBody().size)
                        // RFC 9110 section 8.6: never on a 204; on a 304 only the length a 200 would have (here the body's)
                        assertEquals(if (status == 204) null else "4", r.headers["content-length"], "$status")
                    }
                    // the raw stream: HEADERS, then FIN, no DATA frame
                    for ((method, path) in listOf("HEAD" to "/h", "GET" to "/204", "GET" to "/304")) {
                        val types = rawFrameTypes(c.quic, method, path)
                        assertTrue(types.isNotEmpty() && 0L !in types, "$method $path sent frames $types")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Sends [method] [path] on a fresh bidirectional stream with a hand-made static-free QPACK section; returns the response's frame types. */
    private suspend fun rawFrameTypes(
        quic: io.kuicksilver.quic.QuicConnection,
        method: String,
        path: String,
    ): List<Long> {
        fun int(
            flags: Int,
            prefix: Int,
            v: Int,
            out: kotlinx.io.Buffer,
        ) {
            val max = (1 shl prefix) - 1
            if (v < max) {
                out.writeByte((flags or v).toByte())
                return
            }
            out.writeByte((flags or max).toByte())
            var r = v - max
            while (r >= 128) {
                out.writeByte(((r and 0x7f) or 0x80).toByte())
                r = r shr 7
            }
            out.writeByte(r.toByte())
        }
        val section = kotlinx.io.Buffer()
        section.writeByte(0)
        section.writeByte(0) // Required Insert Count 0, Base 0
        for ((n, v) in listOf(":method" to method, ":scheme" to "https", ":authority" to "server.test", ":path" to path)) {
            int(0x20, 3, n.length, section) // literal field line with literal name, no Huffman (RFC 9204 section 4.5.6)
            section.write(n.encodeToByteArray())
            int(0x00, 7, v.length, section)
            section.write(v.encodeToByteArray())
        }
        val block = section.readByteArray()
        val st = quic.openBidi()
        check(block.size < 16384)
        // HEADERS with a two-byte varint length
        // the server may answer and stop reading (STOP_SENDING with H3_NO_ERROR, RFC 9114 section 4.1) before our FIN leaves
        try {
            st.output.writeFully(byteArrayOf(0x01, (0x40 or (block.size shr 8)).toByte(), block.size.toByte()) + block)
            st.output.flushAndClose()
        } catch (e: Throwable) {
            var c: Throwable? = e
            while (c != null && c !is io.kuicksilver.quic.QuicException.StreamError.Stopped) c = c.cause
            if (c?.code != 0x100L) throw e
        }
        val resp = st.input.readFullBody()
        val types = ArrayList<Long>()
        var i = 0

        fun varint(): Long {
            val len = 1 shl ((resp[i].toInt() and 0xc0) shr 6)
            var v = (resp[i].toLong() and 0x3f)
            for (k in 1 until len) v = (v shl 8) or (resp[i + k].toLong() and 0xff)
            i += len
            return v
        }
        while (i < resp.size) {
            types += varint()
            val len = varint().toInt()
            i += len
        }
        return types
    }

    /**
     * `port = 0`: the UDP twin of the port the OS gave TCP may be taken. The hook occupies it before the first HTTP/3 bind,
     * so that bind fails for real; the server retries the pair and serves h3 and Alt-Svc on one new number. Other
     * processes hold UDP ports too (a parallel test run opens hundreds), so a later pair may also be refused: the contract
     * is "the taken port is skipped, within the budget", not an exact attempt count.
     */
    @Test fun ephemeralPortRetriesWhenUdpTwinIsTaken() = ephemeralPairRetry(occupied = 1)

    /**
     * Every UDP twin of a port the OS gives TCP is taken: what the Windows runner did to a busy test run (CI 40645584772,
     * two ktor-client HTTP/3 tests timed out connecting to a server that served HTTP/1.1 only). Windows hands out TCP ports
     * one after the other, so each TCP-first retry lands on the next number, and a run of UDP ports held by other sockets
     * refuses them all. The server still serves HTTP/3, on a pair whose UDP side the OS picked (port 0) and TCP followed.
     * Red before: sixteen refused twins, then HTTP/1.1 alone.
     */
    @Test fun ephemeralPortServesHttp3WhenEveryTcpTwinIsTaken() = ephemeralPairRetry(occupied = EPHEMERAL_PAIR_ATTEMPTS)

    /**
     * Occupies the UDP twin of the first [occupied] TCP-chosen ports the server tries (a port 0 bind is the UDP side
     * chosen first: nothing to occupy), then checks the retry contract: every taken port is skipped, the server ends on
     * the pair it bound last, TCP and UDP share that number (Alt-Svc names it, h3 answers on it) and it took at most
     * [EPHEMERAL_PAIR_ATTEMPTS] pairs.
     */
    private fun ephemeralPairRetry(occupied: Int) =
        h3ServerTest {
            val taken = ArrayList<DatagramIo>()
            val takenPorts = HashSet<Int>()
            val tried = ArrayList<Int>()
            val bound = ArrayList<Int>()
            val log = CapturedLog()
            val (server, port) =
                tlsServer(configure = {
                    logger = log.quic
                    http3Bind = { a, c, s ->
                        tried += a.port
                        if (a.port != 0 && takenPorts.size < occupied && a.port !in takenPorts) {
                            // Already held by another process: the bind below fails all the same.
                            val held = runCatching { DatagramIo.open(InetSocketAddress("127.0.0.1", a.port)) }
                            held.getOrNull()?.let { taken += it }
                            takenPorts += a.port
                        }
                        Http3Endpoint.bind(a, c, s).also { bound += it.localAddress.port }
                    }
                }, log = log) { routing { get("/") { call.respondText("ok") } } }
            try {
                val why = "taken $takenPorts, tried $tried, bound $bound, serving $port"
                assertTrue(takenPorts.isNotEmpty() && takenPorts.size <= occupied, why)
                assertTrue(tried.size in 2..EPHEMERAL_PAIR_ATTEMPTS, why)
                assertTrue(0 in tried, why) // a pair whose UDP side the OS picked was tried
                assertEquals(port, bound.lastOrNull(), why)
                assertTrue(port !in takenPorts, why)
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: h3=\":$port\""), resp)
                h3(port) { c -> assertEquals(200, c.request(get()).status) }
            } finally {
                server.stop(100, 500)
                taken.forEach { it.close() }
            }
        }

    /**
     * The UDP-first pair loses its TCP twin: the first pair's UDP twin is taken (TCP first), then the hook binds the
     * UDP-first endpoint and holds a TCP listener on the number the OS gave it, so the engine's TCP bind there fails. The
     * engine closes that endpoint and waits until its socket is released (its UDP port can be bound again as soon as the start
     * returns) and the third pair, TCP first again, serves h3.
     */
    @Test fun ephemeralPortUdpFirstPairWhoseTcpTwinIsTakenIsReleased() =
        h3ServerTest {
            val taken = ArrayList<DatagramIo>()
            val tried = ArrayList<Int>()
            val bound = ArrayList<Int>()
            var heldPort = -1
            val selector = SelectorManager(Dispatchers.IO)
            var heldTcp: io.ktor.network.sockets.ServerSocket? = null
            val log = CapturedLog()
            val (server, port) =
                tlsServer(configure = {
                    logger = log.quic
                    http3Bind = { a, c, s ->
                        tried += a.port
                        if (a.port != 0 && tried.size == 1) {
                            // the first pair's UDP twin: already held, the bind below fails all the same
                            runCatching { DatagramIo.open(InetSocketAddress("127.0.0.1", a.port)) }.getOrNull()?.let { taken += it }
                        }
                        Http3Endpoint.bind(a, c, s).also { e ->
                            bound += e.localAddress.port
                            if (a.port == 0 && heldTcp == null) {
                                heldPort = e.localAddress.port
                                heldTcp = bindTcp(selector, "127.0.0.1", heldPort)
                            }
                        }
                    }
                }, log = log) { routing { get("/") { call.respondText("ok") } } }
            try {
                val why = "tried $tried, bound $bound, held TCP $heldPort, serving $port"
                assertTrue(tried.size >= 3 && tried[1] == 0 && tried[2] != 0, why)
                assertTrue(heldPort > 0 && port != heldPort, why)
                assertEquals(port, bound.lastOrNull(), why)
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: h3=\":$port\""), resp)
                h3(port) { c -> assertEquals(200, c.request(get()).status) }
                // the endpoint of the failed UDP-first pair was closed and joined before the start returned: its port can be
                // bound at once (one try, no waiting; the engine owns no socket on it any more)
                val warnings = log.lines.filter { it.level == "WARN" }.map { it.message }
                assertTrue(warnings.none { "was not released" in it }, "the release of UDP $heldPort timed out: $warnings")
                val again = runCatching { DatagramIo.open(InetSocketAddress("127.0.0.1", heldPort)) }
                again.getOrNull()?.close()
                // a failure here with no warning above: the engine joined the endpoint, so another process may have taken the port
                assertTrue(
                    again.isSuccess,
                    "UDP $heldPort still bound after the start returned ($why, warnings $warnings): ${again.exceptionOrNull()}",
                )
            } finally {
                server.stop(100, 500)
                heldTcp?.close()
                selector.close()
                taken.forEach { it.close() }
            }
        }

    /**
     * With port 0 and several endpoint loops on the port (udpSocketCount = 2: a socket per loop with SO_REUSEPORT on Linux
     * and Android, one shared socket elsewhere), a UDP twin in use is retried like any taken port and HTTP/3 is still served
     * (review of 19e3f88b: ksl's refused bind was a KslException, which the engine now takes for a configuration error, so
     * such a start failed). Every platform with a QUIC server serves it since 0.3.0.
     */
    @Test fun ephemeralPortWithSeveralUdpSocketsRetriesATakenTwin() =
        h3ServerTest {
            val selector = SelectorManager(kotlinx.coroutines.Dispatchers.IO)
            val held = ArrayList<io.ktor.network.sockets.BoundDatagramSocket>()
            val tried = ArrayList<Int>()
            val log = CapturedLog()
            try {
                val (server, port) =
                    tlsServer(configure = {
                        udpSocketCount = 2
                        http3Bind = { a, c, st ->
                            tried += a.port
                            if (tried.size ==
                                1
                            ) {
                                held +=
                                    io.ktor.network.sockets
                                        .aSocket(selector)
                                        .udp()
                                        .bind(InetSocketAddress("127.0.0.1", a.port))
                            }
                            Http3Endpoint.bind(a, c, st)
                        }
                    }, log = log) { routing { get("/") { call.respondText("ok") } } }
                try {
                    val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                    val noReusePort = log.lines.any { "SO_REUSEPORT" in it.message || "accelerated transport" in it.message }
                    assertTrue(!noReusePort, "several loops refused: ${log.lines}")
                    assertTrue(tried.size >= 2, "tried $tried")
                    assertTrue(resp.contains("Alt-Svc: h3=\":$port\""), "no HTTP/3 after a taken twin: $resp")
                } finally {
                    server.stop(100, 500)
                }
            } finally {
                held.forEach { it.close() }
                selector.close()
            }
        }

    /** No free twin within [EPHEMERAL_PAIR_ATTEMPTS] pairs: exactly that many tries, then HTTP/1.1 alone, no Alt-Svc. */
    @Test fun ephemeralPortGivesUpHttp3AfterTheBudget() =
        h3ServerTest {
            val tried = ArrayList<Int>()
            val log = CapturedLog()
            val (server, port) =
                tlsServer(configure = {
                    http3Bind = { a, _, _ ->
                        tried += a.port
                        throw kotlinx.io.IOException("UDP ${a.port}: Address already in use")
                    }
                }, log = log) { routing { get("/") { call.respondText("ok") } } }
            try {
                assertEquals(EPHEMERAL_PAIR_ATTEMPTS, tried.size, "tried $tried")
                log.assertLogged("WARN", "HTTP/3 is not served: no TCP + UDP pair free on one port number")
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.endsWith("ok") && !resp.contains("Alt-Svc"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * With `port = 0` only a failure to bind is a reason to try another pair (review 2026-10-28 last3 R2): an HTTP/3
     * configuration the endpoint refuses fails the start at the first attempt, as with a fixed port, instead of being
     * tried [EPHEMERAL_PAIR_ATTEMPTS] times and then dropped for HTTP/1.1 with a warning.
     */
    @Test fun negative_ephemeralPortDoesNotRetryAConfigurationError() =
        h3ServerTest {
            val refusals: List<() -> Throwable> =
                listOf(
                    { IllegalArgumentException("the server TLS configuration must offer ALPN \"h3\"") },
                    // a native-layer failure (loading, ABI, OpenSSL internals) is no taken port either (review NIT)
                    {
                        io.kuicksilver.native.KslException
                            .Internal(0, 0, "ksl: the context refused the identity")
                    },
                )
            for (refusal in refusals) {
                val tried = ArrayList<Int>()
                val failure =
                    assertFails {
                        tlsServer(configure = {
                            http3Bind = { a, _, _ ->
                                tried += a.port
                                throw refusal()
                            }
                        }) { routing { get("/") { call.respondText("ok") } } }.first.stop(100, 500)
                    }
                assertEquals(1, tried.size, "tried $tried ($failure)")
                val expected = refusal()::class
                assertTrue(
                    generateSequence(failure) { it.cause }.any { expected.isInstance(it) },
                    "the start failed with $failure, not with the configuration error",
                )
            }
        }

    @Test fun altSvcOnH1Responses() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: h3=\":$port\"; ma=86400"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun altSvcDisabled() =
        h3ServerTest {
            val (server, port) = tlsServer(configure = { altSvc = false }) { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(!resp.contains("Alt-Svc"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun appAltSvcNotOverwritten() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "clear")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: clear") && !resp.contains("h3="), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun hundredRequestsOneConnection() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/{n}") { call.respondText("n=${call.parameters["n"]}") } } }
            try {
                h3(port) { c ->
                    val bodies =
                        coroutineScope {
                            (0 until 100)
                                .map { i ->
                                    async {
                                        c
                                            .request(get("/$i"))
                                            .body
                                            .readFullBody()
                                            .decodeToString()
                                    }
                                }.awaitAll()
                        }
                    assertEquals(
                        (
                            0 until
                                100
                        ).map { "n=$it" },
                        bodies,
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun h3ResponseHeadersAreLowercase() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("X-Custom-Header", "v")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                h3(port) { c -> assertEquals("v", c.request(get()).headers["x-custom-header"]) }
            } finally {
                server.stop(100, 500)
            }
        }

    /** `stop(grace, timeout)` is honoured for HTTP/3 too — in-flight calls finish, the client sees GOAWAY. */
    @Test fun stopWaitsForInFlightH3Call() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/slow") {
                            kotlinx.coroutines.delay(1500)
                            call.respondText("done")
                        }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                try {
                    coroutineScope {
                        val response = async { c.request(get("/slow")) }
                        kotlinx.coroutines.delay(300)
                        val t0 =
                            kotlin.time.TimeSource.Monotonic
                                .markNow()
                        server.stopSuspend(5000, 10000)
                        val stopTook = t0.elapsedNow()
                        val r = response.await()
                        assertEquals(200, r.status)
                        assertEquals("done", r.body.readFullBody().decodeToString())
                        assertTrue(stopTook < 4.seconds && stopTook > 500.milliseconds, "stop waited for the call: $stopTook")
                        assertEquals(
                            true,
                            kotlinx.coroutines.withTimeoutOrNull(3.seconds) {
                                while (c.goAwayReceived.value ==
                                    null
                                ) {
                                    kotlinx.coroutines.delay(20)
                                }
                                true
                            },
                            "the client received GOAWAY",
                        )
                    }
                } finally {
                    c.close()
                }
            } finally {
                ep.close()
                runCatching { server.stop(100, 500) }
            }
        }

    /** GOAWAY reaches every connection at once, not one per 2×RTT; the in-flight calls all finish within the grace period. */
    @Test fun stopSendsGoAwayToAllConnectionsAtOnce() =
        h3ServerTest {
            val arrived = kotlin.concurrent.atomics.AtomicInt(0)
            val (server, port) =
                tlsServer {
                    routing {
                        get("/slow") {
                            arrived.addAndFetch(1)
                            kotlinx.coroutines.delay(600)
                            call.respondText("done")
                        }
                    }
                }
            val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
            val conns = ArrayList<Http3Connection>()
            try {
                repeat(50) { conns += ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3"))) }
                coroutineScope {
                    val responses =
                        conns.map { c ->
                            async {
                                c.request(get("/slow")).let { r ->
                                    r.status to
                                        r.body.readFullBody().decodeToString()
                                }
                            }
                        }
                    kotlinx.coroutines.withTimeout(5.seconds) { while (arrived.load() < 50) kotlinx.coroutines.delay(10) }
                    val t0 =
                        kotlin.time.TimeSource.Monotonic
                            .markNow()
                    // the grace period covers the calls' 600 ms, the server's 50 ms between its two GOAWAYs and the ~200 ms it
                    // gives the last responses before closing; on a coarse timer that is over 1 s (seen 1.02-1.25 s on a loaded
                    // macOS host, every run), and the deadline then cuts responses still in flight
                    val stop = async(kotlinx.coroutines.Dispatchers.Default) { server.stop(5000, 8000) }
                    kotlinx.coroutines.withTimeout(
                        5.seconds,
                    ) { while (conns.any { it.goAwayReceived.value == null }) kotlinx.coroutines.delay(5) }
                    val allSawGoAway = t0.elapsedNow()
                    assertEquals(List(50) { 200 to "done" }, responses.awaitAll())
                    stop.await()
                    // at once is one round of the server's 50 ms wait between its two GOAWAYs (~200 ms on a coarse timer, up to
                    // 406 ms seen); one connection after another would be 50 such rounds, 2.5 s even on an idle host
                    assertTrue(allSawGoAway < 1.seconds, "every client saw GOAWAY after $allSawGoAway")
                }
            } finally {
                conns.forEach { it.close() }
                ep.close()
                runCatching { server.stop(100, 500) }
            }
        }

    /**
     * A client that keeps its idle HTTP/3 connection open after the stop's GOAWAY (a browser, curl; a Kuicksilver client
     * closes it) was closed by the server only three seconds after the final GOAWAY, so a stop with a shorter grace period
     * (Ktor's `stop(500, 500)`, `stop(1000, 2000)`) always ran out its grace and cut every connection left instead of
     * draining it. The wait is now a quarter of the grace period.
     */
    @Test fun aStopShorterThanThreeSecondsEndsGracefullyWithAnIdleClient() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            val idle = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                // a QUIC connection with ALPN h3 that sends nothing and never closes: the idle browser connection
                idle.connect(
                    InetSocketAddress("127.0.0.1", port),
                    QuicClientConfig.Builder(ServerFixtures.clientTls(alpn = listOf("h3"))).build(),
                )
                kotlinx.coroutines.withTimeout(5.seconds) {
                    while (server.engine.h3ListenersForProbe.sumOf { it.size() } == 0) delay(10)
                }
                server.engine.stopSuspend(1000, 3000)
                assertFalse(server.engine.stopWasForcedForTest, "the stop ran out its grace period")
            } finally {
                idle.close()
                runCatching { server.stop(100, 500) }
            }
        }

    /**
     * A client whose transport parameters allow fewer than the three unidirectional streams HTTP/3 needs (RFC 9114 section
     * 6.2), connected and silent, held the HTTP/3 accept loop: no later client was served (0.2.1 review).
     */
    @Test fun negative_clientWithoutUniStreamCreditDoesNotStopAccepting() =
        h3ServerTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            val stuck = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                stuck.connect(
                    InetSocketAddress("127.0.0.1", port),
                    QuicClientConfig
                        .Builder(ServerFixtures.clientTls(alpn = listOf("h3")))
                        .apply { quic = quicConfig { maxUniStreams = 2 } }
                        .build(),
                )
                kotlinx.coroutines.withTimeout(15.seconds) {
                    h3(port) { c ->
                        val r = c.request(get())
                        assertEquals(200, r.status)
                        assertEquals("ok", r.body.readFullBody().decodeToString())
                    }
                }
            } finally {
                stuck.close()
                server.stop(100, 500)
            }
        }

    /**
     * `call.request.local.scheme` is the request's `:scheme`, and `serverPort` without a port in `:authority` is that
     * scheme's default port: an `http` request over HTTP/3 (RFC 9114 section 3.1.2, a gateway or an origin that is
     * authoritative for it) was reported as `https` on port 443.
     */
    @Test fun schemeAndDefaultPortFollowTheRequest() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing { get("/") { call.respondText("${call.request.local.scheme} ${call.request.local.serverPort}") } }
                }
            try {
                h3(port) { c ->
                    for ((scheme, expected) in listOf("http" to "http 80", "https" to "https 443")) {
                        val r = c.request(http3Request("GET", "server.test", "/") { this.scheme = scheme })
                        assertEquals(expected, r.body.readFullBody().decodeToString())
                    }
                    val r = c.request(http3Request("GET", "server.test:8443", "/") { this.scheme = "http" })
                    assertEquals("http 8443", r.body.readFullBody().decodeToString())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Split `cookie` fields are one header for the application (RFC 9114 section 4.2.1). */
    @Test fun cookieCrumbsAreJoined() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing { get("/") { call.respondText("${call.request.headers["Cookie"]}|${call.request.cookies["b"]}") } }
                }
            try {
                h3(port) { c ->
                    val r =
                        c.request(
                            http3Request("GET", "server.test", "/") {
                                headers =
                                    io.kuicksilver.http3.Http3Headers
                                        .of("cookie" to "a=1", "cookie" to "b=2")
                            },
                        )
                    assertEquals("a=1; b=2|2", r.body.readFullBody().decodeToString())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Ktor allows optional whitespace around a header value; HTTP/3 does not carry it. The value is trimmed instead of hanging the stream. */
    @Test fun headerWithTrailingSpaceDoesNotHang() =
        h3ServerTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.response.header("X-A", "v ")
                            call.respondText("ok")
                        }
                    }
                }
            try {
                h3(port) { c ->
                    val r = kotlinx.coroutines.withTimeout(5.seconds) { c.request(get()) }
                    assertEquals(200, r.status)
                    assertEquals("v", r.headers["x-a"])
                    assertEquals("ok", r.body.readFullBody().decodeToString())
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
