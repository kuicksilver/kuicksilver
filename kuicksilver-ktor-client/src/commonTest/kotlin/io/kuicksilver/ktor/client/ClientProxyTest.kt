// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.http.cio.ParserException
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.copyAndClose
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** HTTPS through an HTTP proxy: a CONNECT tunnel (RFC 9110 section 9.3.6) to the TLS origin. */
class ClientProxyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * Proxy-Authorization is for the proxy that asked for it (RFC 9110 section 11.7.2): it goes on the CONNECT, never inside
     * the tunnel to the origin; nor does Proxy-Connection.
     */
    @Test fun negative_proxyCredentialsStayOnTheConnect() =
        clientTest {
            val (server, port) =
                testServer {
                    routing {
                        get("/") {
                            val h = call.request.headers
                            call.respondText("${h[HttpHeaders.ProxyAuthorization]}|${h["Proxy-Connection"]}")
                        }
                    }
                }
            try {
                tunnelProxy(port) { proxyPort, connectHead ->
                    testClient(engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) }).use { c ->
                        val body =
                            c
                                .get("https://127.0.0.1:$port/") {
                                    header(HttpHeaders.ProxyAuthorization, "Basic cHJveHk6c2VjcmV0")
                                    header("Proxy-Connection", "keep-alive")
                                }.bodyAsText()
                        assertEquals("null|null", body, "the origin received proxy fields through the tunnel")
                        assertEquals(true, connectHead().any { it == "Proxy-Authorization: Basic cHJveHk6c2VjcmV0" })
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A client MUST ignore Content-Length and Transfer-Encoding in a 2xx response to CONNECT (RFC 9110 section 9.3.6): the
     * bytes after the head are the tunnel's. A proxy that sends `Content-Length: 5` must not make the client wait for five
     * bytes before its ClientHello.
     */
    @Test fun contentLengthOnConnectResponseIsIgnored() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("through") } } }
            try {
                tunnelProxy(port, connectResponse = "HTTP/1.1 200 Connection established\r\nContent-Length: 5\r\n\r\n") { proxyPort, _ ->
                    testClient(engine = {
                        proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort"))
                        connectTimeout = 5.seconds
                    }).use { c ->
                        assertEquals("through", c.get("https://127.0.0.1:$port/").bodyAsText())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A client MUST be able to parse 1xx responses before the final one (RFC 9110 section 15.2), the CONNECT's included:
     * a 100 and a 103 from the proxy are skipped and its 200 opens the tunnel. Before, the first 1xx failed the tunnel
     * with an IOException.
     */
    @Test fun interimResponsesBeforeTheConnectAnswerAreSkipped() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("through") } } }
            try {
                val interim = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"
                tunnelProxy(port, connectResponse = interim + "HTTP/1.1 200 Connection established\r\n\r\n") { proxyPort, _ ->
                    testClient(engine = {
                        proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort"))
                        connectTimeout = 5.seconds
                    }).use { c ->
                        assertEquals("through", c.get("https://127.0.0.1:$port/").bodyAsText())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A client MUST wait for a 2xx to its CONNECT before it sends tunnel data, or say `Connection: close` (RFC 9931 section
     * 8); this one waits. A proxy that refuses the CONNECT with 407 receives nothing after the CONNECT head, no TLS
     * ClientHello, up to the client's close: early bytes would land before it whenever they were sent, so no time window
     * is needed.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_noTunnelByteBeforeTheConnectAnswer() =
        clientTest {
            val selector = SelectorManager(Dispatchers.Default)
            val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
            try {
                coroutineScope {
                    // per connection: the CONNECT line and the bytes that followed its head until the client closed
                    val seen =
                        async {
                            List(1) {
                                listener.accept().use { s ->
                                    val input = s.openReadChannel()
                                    val output = s.openWriteChannel(autoFlush = true)
                                    val line = input.readUTF8Line().orEmpty()
                                    while (input.readUTF8Line()?.isNotEmpty() == true) continue
                                    output.writeStringUtf8("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                                    val after = withTimeout(10.seconds) { runCatching { input.readRemaining().readByteArray() } }
                                    line to after.getOrElse { ByteArray(0) }.size
                                }
                            }
                        }
                    val proxyPort = (listener.localAddress as InetSocketAddress).port
                    testClient(engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) }).use { c ->
                        val refused = assertFailsWith<IOException> { c.get("https://127.0.0.1:1/").bodyAsText() }
                        assertTrue(refused.message!!.endsWith(": 407"), refused.message)
                    }
                    assertEquals(
                        listOf("CONNECT 127.0.0.1:1 HTTP/1.1" to 0),
                        seen.await(),
                        "bytes after the CONNECT head before its answer",
                    )
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * HTTP/3 cannot go through the proxy (no UDP over HTTP CONNECT or SOCKS5), so `H3Only` with a proxy fails the request
     * without contacting the proxy. Before, the request silently went over HTTP/1.1 through the proxy, the opposite of
     * what `H3Only` promises (failures are reported, never retried over TCP).
     */
    @Test fun negative_h3OnlyWithAProxyFails() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("through") } } }
            try {
                tunnelProxy(port) { proxyPort, connectHead ->
                    testClient(Http3DiscoveryMode.H3Only, engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) })
                        .use { c ->
                            val e = assertFailsWith<UnsupportedOperationException> { c.get("https://127.0.0.1:$port/").bodyAsText() }
                            assertTrue(e.message!!.contains("HTTP/3") && e.message!!.contains("proxy"), e.message)
                            assertEquals(emptyList<String>(), connectHead(), "the proxy was contacted")
                        }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A proxy that answers the CONNECT with a 4 MiB head: the client stops reading at 64 KiB, fails the request with a
     * ParserException naming the limit and closes the connection. Before, the CONNECT response head had no size limit.
     */
    @Test fun negative_hugeConnectResponseHeadFails() =
        clientTest {
            val selector = SelectorManager(Dispatchers.Default)
            val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
            try {
                coroutineScope {
                    val proxyClosedBy =
                        async {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                val output = s.openWriteChannel(autoFlush = false)
                                while (input.readUTF8Line()?.isNotEmpty() == true) continue
                                runCatching {
                                    output.writeStringUtf8("HTTP/1.1 200 Connection established\r\n")
                                    repeat(1024) { output.writeStringUtf8("X-Pad: " + "p".repeat(4000) + "\r\n") }
                                    output.writeStringUtf8("\r\n")
                                    output.flush()
                                }
                                // the client closes its side once it gives up on the head; with the rest of the head
                                // unread there, the close may arrive as a reset
                                withTimeout(10.seconds) {
                                    try {
                                        input.awaitContent()
                                    } catch (_: kotlinx.io.IOException) {
                                        false
                                    }
                                }
                            }
                        }
                    val proxyPort = (listener.localAddress as InetSocketAddress).port
                    testClient(engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) }).use { c ->
                        val e = assertFailsWith<ParserException> { c.get("https://127.0.0.1:1/").bodyAsText() }
                        assertTrue(e.message!!.contains("65536"), e.message)
                    }
                    assertEquals(false, proxyClosedBy.await(), "the client kept the proxy connection open")
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /** `Auto` with a proxy keeps using HTTP/1.1 through it (HTTP/3 is not attempted, Alt-Svc is not used). */
    @Test fun autoWithAProxyUsesHttp11ThroughIt() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("through") } } }
            try {
                tunnelProxy(port) { proxyPort, _ ->
                    testClient(Http3DiscoveryMode.Auto, engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) })
                        .use { c ->
                            val r = c.get("https://127.0.0.1:$port/")
                            assertEquals("through", r.bodyAsText())
                            assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9110 section 4.2.4: the origin's userinfo (and its "@") must never be generated in a target URI; RFC 9110
     * section 7.1 / RFC 9112 section 3.2.2: the fragment is not part of the absolute-form, nor of the Host field.
     */
    @Test fun negative_absoluteFormHasNoUserinfoOrFragment() =
        clientTest {
            val lines = proxiedHead("http://alice:s3cret@origin.test:8080/x?q=1#top")
            assertEquals("GET http://origin.test:8080/x?q=1 HTTP/1.1", lines.first())
            assertTrue("Host: origin.test:8080" in lines, "$lines")
            assertTrue(lines.none { "s3cret" in it || "alice" in it || "#top" in it }, "$lines")
        }

    @Test fun negative_absoluteFormWithDefaultPortAndEmptyPathHasNoUserinfo() =
        clientTest {
            val lines = proxiedHead("http://alice:s3cret@origin.test#top")
            assertEquals("GET http://origin.test/ HTTP/1.1", lines.first())
            assertTrue("Host: origin.test" in lines, "$lines")
            assertTrue(lines.none { "s3cret" in it || "alice" in it || "#top" in it }, "$lines")
        }

    /** The request head a plain HTTP proxy receives for a GET of [url]; the proxy answers 200 "ok". */
    private suspend fun proxiedHead(url: String): List<String> {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
        try {
            return coroutineScope {
                val head =
                    async {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            val lines = ArrayList<String>()
                            while (true) {
                                val line = input.readUTF8Line() ?: break
                                if (line.isEmpty()) break
                                lines += line
                            }
                            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                            lines
                        }
                    }
                val proxyPort = (listener.localAddress as InetSocketAddress).port
                testClient(engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) }).use { c ->
                    assertEquals("ok", c.get(url).bodyAsText())
                }
                head.await()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /**
     * A one-connection CONNECT proxy to 127.0.0.1:[originPort]: answers the CONNECT with [connectResponse], then copies bytes
     * both ways. [block] gets its port and the CONNECT head's lines (once the CONNECT was read).
     */
    private suspend fun tunnelProxy(
        originPort: Int,
        connectResponse: String = "HTTP/1.1 200 Connection established\r\n\r\n",
        block: suspend (Int, () -> List<String>) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
        val head = ArrayList<String>()
        try {
            coroutineScope {
                val proxy =
                    launch {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            while (true) {
                                val line = input.readUTF8Line() ?: return@launch
                                if (line.isEmpty()) break
                                head += line
                            }
                            aSocket(selector).tcp().connect("127.0.0.1", originPort).use { o ->
                                output.writeStringUtf8(connectResponse)
                                val oIn = o.openReadChannel()
                                val oOut = o.openWriteChannel(autoFlush = true)
                                coroutineScope {
                                    launch { pump(input, oOut) }
                                    pump(oIn, output)
                                }
                            }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port) { head.toList() }
                proxy.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    private suspend fun pump(
        from: ByteReadChannel,
        to: io.ktor.utils.io.ByteWriteChannel,
    ) {
        runCatching { from.copyAndClose(to) }
    }
}
