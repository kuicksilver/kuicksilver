// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.install
import io.ktor.server.request.uri
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.copyAndClose
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readFully
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.ktor.server.websocket.WebSockets as ServerWebSockets
import io.ktor.server.websocket.webSocket as serverWebSocket

/** SOCKS5 proxies (RFC 1928, RFC 1929) and the HTTP proxy's CONNECT for WebSockets, through hand-driven loopback proxies. */
class ClientSocksProxyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * RFC 1929 section 2 gives PASSWD 1 to 255 octets (PLEN 1..255), so a SOCKS5 proxy with an empty password is refused
     * when it is configured: the engine's `proxy` with such `proxyCredentials` fails the engine's creation, and
     * `ResolvedProxy.socks5` fails at once. An empty password stays allowed for an HTTP proxy (`Basic`, RFC 7617).
     */
    @Test fun negative_socks5ProxyWithAnEmptyPasswordIsAConfigurationError() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                HttpClient(Kuicksilver) {
                    engine {
                        proxy = ProxyBuilder.socks("127.0.0.1", 1080)
                        proxyCredentials = ProxyCredentials("u", "")
                    }
                }.close()
            }
        assertTrue(e.message!!.contains("RFC 1929"), e.message)
        assertFailsWith<IllegalArgumentException> { ResolvedProxy.socks5("proxy.test", 1080, ProxyCredentials("u", "")) }
        assertFailsWith<IllegalArgumentException> { ResolvedProxy.socks5("proxy.test", 1080, ProxyCredentials("u", "p".repeat(256))) }
        ResolvedProxy.socks5("proxy.test", 1080, ProxyCredentials("u", "p"))
        ResolvedProxy.http("proxy.test", 3128, ProxyCredentials("u", ""))
        HttpClient(Kuicksilver) {
            engine {
                proxy = ProxyBuilder.http(Url("http://127.0.0.1:3128"))
                proxyCredentials = ProxyCredentials("u", "")
            }
        }.close()
    }

    /** What a [socksProxy] saw: the methods offered, the RFC 1929 credentials, the CONNECT's ATYP and destination bytes. */
    private class Seen {
        val methods = CompletableDeferred<List<Int>>()
        val credentials = CompletableDeferred<Pair<String, String>?>()
        val atyp = CompletableDeferred<Int>()
        val destination = CompletableDeferred<ByteArray>()
    }

    /**
     * A one-connection SOCKS5 proxy relaying to 127.0.0.1:[originPort]: picks username/password when [auth] is set (and
     * then accepts exactly those), else "no authentication"; answers the CONNECT with [reply].
     */
    private suspend fun socksProxy(
        originPort: Int,
        auth: ProxyCredentials? = null,
        reply: Int = 0,
        block: suspend (Int, Seen) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
        val seen = Seen()
        try {
            coroutineScope {
                val proxy =
                    launch {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            check(input.readByte() == 5.toByte())
                            val n = input.readByte().toInt()
                            seen.methods.complete(List(n) { input.readByte().toInt() and 0xff })
                            if (auth != null) {
                                output.writeFully(byteArrayOf(5, 2))
                                check(input.readByte() == 1.toByte())
                                val user = ByteArray(input.readByte().toInt() and 0xff).also { input.readFully(it) }.decodeToString()
                                val pass = ByteArray(input.readByte().toInt() and 0xff).also { input.readFully(it) }.decodeToString()
                                seen.credentials.complete(user to pass)
                                val good = user == auth.user && pass == auth.password
                                output.writeFully(byteArrayOf(1, if (good) 0 else 1))
                                if (!good) return@launch
                            } else {
                                seen.credentials.complete(null)
                                output.writeFully(byteArrayOf(5, 0))
                            }
                            val head = ByteArray(4).also { input.readFully(it) }
                            seen.atyp.complete(head[3].toInt())
                            val dest =
                                when (head[3].toInt()) {
                                    1 -> ByteArray(4)
                                    4 -> ByteArray(16)
                                    else -> ByteArray(input.readByte().toInt() and 0xff)
                                }.also { input.readFully(it) }
                            seen.destination.complete(dest)
                            input.readFully(ByteArray(2))
                            if (reply != 0) {
                                output.writeFully(byteArrayOf(5, reply.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
                                return@launch
                            }
                            aSocket(selector).tcp().connect("127.0.0.1", originPort).use { o ->
                                output.writeFully(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0))
                                val oIn = o.openReadChannel()
                                val oOut = o.openWriteChannel(autoFlush = true)
                                coroutineScope {
                                    launch { pump(input, oOut) }
                                    pump(oIn, output)
                                }
                            }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port, seen)
                proxy.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    private suspend fun pump(
        from: ByteReadChannel,
        to: ByteWriteChannel,
    ) {
        runCatching { from.copyAndClose(to) }
    }

    @Test fun httpsThroughSocks5() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("through") } } }
            try {
                socksProxy(port) { proxyPort, seen ->
                    testClient(engine = { proxy = ProxyBuilder.socks("127.0.0.1", proxyPort) }).use { c ->
                        val r = c.get("https://127.0.0.1:$port/") // TLS verifies the origin's certificate inside the tunnel
                        assertEquals("through", r.bodyAsText())
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals(listOf(0), seen.methods.await(), "only 'no authentication' without credentials")
                        assertEquals(1, seen.atyp.await())
                        assertContentEquals(byteArrayOf(127, 0, 0, 1), seen.destination.await())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun socks5UsernamePassword() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("authenticated") } } }
            try {
                socksProxy(port, auth = ProxyCredentials("alice", "pw")) { proxyPort, seen ->
                    testClient(engine = {
                        proxy = ProxyBuilder.socks("127.0.0.1", proxyPort)
                        proxyCredentials = ProxyCredentials("alice", "pw")
                    }).use { c ->
                        assertEquals("authenticated", c.get("https://127.0.0.1:$port/").bodyAsText())
                        assertEquals(listOf(0, 2), seen.methods.await())
                        assertEquals("alice" to "pw", seen.credentials.await())
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun plainHttpThroughSocksUsesOriginForm() =
        clientTest {
            val (server, port) = testServer(plain = true) { routing { get("/p") { call.respondText(call.request.uri) } } }
            try {
                socksProxy(port) { proxyPort, _ ->
                    testClient(engine = { proxy = ProxyBuilder.socks("127.0.0.1", proxyPort) }).use { c ->
                        assertEquals("/p", c.get("http://127.0.0.1:$port/p").bodyAsText(), "the absolute form went to the origin")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Through `socks5://` (names resolved by the client) a "host unreachable" for the first address of the origin moves
     * on to the next one, on a new connection to the proxy.
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @Test
    fun socks5LocalDnsTriesNextAddressOnUnreachable() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("second address") } } }
            val selector = SelectorManager(Dispatchers.Default)
            val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
            val destinations = ArrayList<List<Byte>>()
            try {
                coroutineScope {
                    val proxy =
                        launch {
                            for (attempt in 0..1) {
                                listener.accept().use { s ->
                                    val input = s.openReadChannel()
                                    val output = s.openWriteChannel(autoFlush = true)
                                    input.readFully(ByteArray(3)) // 05 01 00: no authentication only
                                    output.writeFully(byteArrayOf(5, 0))
                                    val head = ByteArray(4).also { input.readFully(it) }
                                    check(head[3] == 1.toByte()) { "an address was expected, not ATYP ${head[3]}" }
                                    destinations += ByteArray(4).also { input.readFully(it) }.toList()
                                    input.readFully(ByteArray(2))
                                    if (attempt == 0) {
                                        output.writeFully(byteArrayOf(5, 4, 0, 1, 0, 0, 0, 0, 0, 0)) // host unreachable
                                    } else {
                                        aSocket(selector).tcp().connect("127.0.0.1", port).use { o ->
                                            output.writeFully(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0))
                                            val oIn = o.openReadChannel()
                                            val oOut = o.openWriteChannel(autoFlush = true)
                                            coroutineScope {
                                                launch { pump(input, oOut) }
                                                pump(oIn, output)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    val proxyPort = (listener.localAddress as InetSocketAddress).port
                    testClient(engine = {
                        proxyResolver = environmentResolver(mapOf("all_proxy" to "socks5://127.0.0.1:$proxyPort"))
                        resolverForTest = { host, p ->
                            if (host == "server.test") {
                                listOf(
                                    io.kuicksilver.ktor.network
                                        .TcpAddress(byteArrayOf(10, -1, -1, 1), p),
                                    io.kuicksilver.ktor.network
                                        .TcpAddress(byteArrayOf(127, 0, 0, 1), p),
                                )
                            } else {
                                listOf(
                                    io.kuicksilver.ktor.network
                                        .TcpAddress(byteArrayOf(127, 0, 0, 1), p),
                                )
                            }
                        }
                    }).use { c ->
                        assertEquals("second address", c.get("https://server.test:$port/").bodyAsText())
                    }
                    assertEquals(listOf(listOf<Byte>(10, -1, -1, 1), listOf<Byte>(127, 0, 0, 1)), destinations)
                    proxy.cancel()
                }
            } finally {
                listener.close()
                selector.close()
                server.stop(100, 500)
            }
        }

    @Test fun negative_socksReplyFailsTheRequest() =
        clientTest {
            socksProxy(1, reply = 5) { proxyPort, _ ->
                testClient(engine = { proxy = ProxyBuilder.socks("127.0.0.1", proxyPort) }).use { c ->
                    val e = assertFailsWith<ProxyException> { c.get("https://127.0.0.1:1/").bodyAsText() }
                    assertEquals(5, e.replyCode)
                }
            }
        }

    @Test fun negative_socksH3OnlyFails() =
        clientTest {
            socksProxy(1) { proxyPort, seen ->
                testClient(Http3DiscoveryMode.H3Only, engine = { proxy = ProxyBuilder.socks("127.0.0.1", proxyPort) }).use { c ->
                    assertFailsWith<UnsupportedOperationException> { c.get("https://127.0.0.1:1/").bodyAsText() }
                    assertTrue(!seen.methods.isCompleted, "the proxy was contacted")
                }
            }
        }

    /** RFC 6455 section 4.1 item 2: a ws:// WebSocket goes through an HTTP proxy in a CONNECT tunnel, as browsers do. */
    @Test fun wsThroughHttpProxyUsesConnect() =
        clientTest {
            val (server, port) =
                testServer(plain = true) {
                    install(ServerWebSockets)
                    routing { serverWebSocket("/ws") { send(Frame.Text("hello")) } }
                }
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    testClient(engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) }, block = { install(WebSockets) })
                        .use { c ->
                            c.webSocket("ws://127.0.0.1:$port/ws") {
                                assertEquals("hello", (withTimeout(5.seconds) { incoming.receive() } as Frame.Text).readText())
                            }
                            assertEquals("CONNECT 127.0.0.1:$port HTTP/1.1", head().first())
                        }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun connect407FailsWithProxyException() =
        clientTest {
            val refusal = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"p\"\r\nContent-Length: 0\r\n\r\n"
            val (server, port) = testServer { routing { get("/") { call.respondText("unreachable") } } }
            try {
                ClientProxyTest().tunnelProxy(port, connectResponse = refusal) { proxyPort, _ ->
                    testClient(engine = { proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort")) }).use { c ->
                        val e = assertFailsWith<ProxyException> { c.get("https://127.0.0.1:$port/").bodyAsText() }
                        assertEquals(407, e.replyCode)
                        assertTrue("credentials" in e.message!!, e.message)
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** `proxyCredentials` go on the CONNECT at once as `Basic` (no 407 round trip), and never into the tunnel. */
    @Test fun proxyCredentialsSentPreemptivelyOnConnect() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("${call.request.headers["Proxy-Authorization"]}") } } }
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    testClient(engine = {
                        proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort"))
                        proxyCredentials = ProxyCredentials("u", "p")
                    }).use { c ->
                        assertEquals("null", c.get("https://127.0.0.1:$port/").bodyAsText())
                        assertTrue("Proxy-Authorization: Basic dTpw" in head(), "${head()}")
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
                                val line = input.readLine(LineEnding.Lenient) ?: break
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

    /** Plain http through an HTTP proxy: the absolute form, with the configured credentials as `Basic`. */
    @Test fun absoluteFormCarriesProxyCredentials() =
        clientTest {
            val selector = SelectorManager(Dispatchers.Default)
            val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
            try {
                coroutineScope {
                    val head =
                        async {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                val output = s.openWriteChannel(autoFlush = true)
                                val lines = ArrayList<String>()
                                while (true) {
                                    val line = input.readLine(LineEnding.Lenient) ?: break
                                    if (line.isEmpty()) break
                                    lines += line
                                }
                                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                                lines
                            }
                        }
                    val proxyPort = (listener.localAddress as InetSocketAddress).port
                    testClient(engine = {
                        proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort"))
                        proxyCredentials = ProxyCredentials("u", "p")
                    }).use { c ->
                        assertEquals("ok", c.get("http://origin.test:8080/x").bodyAsText())
                    }
                    val lines = head.await()
                    assertEquals("GET http://origin.test:8080/x HTTP/1.1", lines.first())
                    assertTrue("Proxy-Authorization: Basic dTpw" in lines, "$lines")
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    @Test fun protocolSelectedReasonIsProxy() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, _ ->
                    val reasons = ArrayList<ProtocolReason>()
                    val listener =
                        object : KuicksilverEventListener() {
                            override fun protocolSelected(
                                request: HttpRequestData,
                                protocol: HttpProtocolVersion,
                                reason: ProtocolReason,
                            ) {
                                reasons += reason
                            }
                        }
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort"))
                        eventListener = listener
                    }).use { c ->
                        assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                        assertEquals(listOf(ProtocolReason.Proxy), reasons)
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
