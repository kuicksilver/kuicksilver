// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
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
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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
