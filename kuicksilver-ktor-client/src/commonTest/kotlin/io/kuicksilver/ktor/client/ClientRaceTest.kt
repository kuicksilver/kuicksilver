// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.tlsServer
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** The h3/h1 connection race (RFC 8305 section 5, RFC 7838 section 2.4) against servers whose QUIC side never answers. */
class ClientRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * An idle pooled HTTP/1.1 connection the race hands out is a pooled connection: when the server closed it, an
     * idempotent request gets the same one transparent retry as on the plain HTTP/1.1 path (RFC 9112 section 9.3.1).
     * Before, the race's connection counted as fresh and the GET failed.
     */
    @Test fun staleConnectionFromTheRaceIsRetried() =
        clientTest {
            val served = ArrayList<String>()
            tlsServerWithSilentUdp({ index, input, output ->
                served += "$index:${readHead(input)}"
                output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                if (index == 0) {
                    served += "$index:${readHead(input)}" // the second request on the pooled connection: closed unanswered
                } else {
                    readHead(input)
                }
            }) { port ->
                // the HTTP/3 setup stays pending (UDP is silent), so the race runs again for the second request
                testClient(Http3DiscoveryMode.Preferred, engine = { connectTimeout = 30.seconds }).use { c ->
                    val r1 = c.get("https://127.0.0.1:$port/1")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r1.version)
                    assertEquals("ok", r1.bodyAsText())
                    assertEquals("ok", c.get("https://127.0.0.1:$port/2").bodyAsText())
                }
            }
            assertEquals(listOf("0:GET /1 HTTP/1.1", "0:GET /2 HTTP/1.1", "1:GET /2 HTTP/1.1"), served)
        }

    /** Reads a request head; returns its request line ("" at end of stream). */
    private suspend fun readHead(input: ByteReadChannel): String {
        val line = input.readUTF8Line() ?: return ""
        while (input.readUTF8Line()?.isNotEmpty() == true) Unit
        return line
    }

    /**
     * A TLS (HTTP/1.1) listener on 127.0.0.1 that runs [handler] once per accepted connection with its index, then closes
     * it; the UDP port of the same number is bound and never answers (QUIC blocked).
     */
    private suspend fun tlsServerWithSilentUdp(
        handler: suspend CoroutineScope.(index: Int, input: ByteReadChannel, output: ByteWriteChannel) -> Unit,
        block: suspend (Int) -> Unit,
    ) {
        val tls =
            tlsConfig(TlsRole.Server) {
                identity = ClientFixtures.identity()
                alpn = listOf("http/1.1")
            }
        val selector = SelectorManager(Dispatchers.Default)
        val listener = aSocket(selector).tcp().bind("127.0.0.1", 0)
        val port = (listener.localAddress as InetSocketAddress).port
        val udp = aSocket(selector).udp().bind(InetSocketAddress("127.0.0.1", port))
        try {
            coroutineScope {
                val server =
                    launch {
                        var index = 0
                        while (true) {
                            val raw = listener.accept()
                            val i = index++
                            launch {
                                runCatching {
                                    raw.tlsServer(tls).use { s -> handler(i, s.openReadChannel(), s.openWriteChannel(autoFlush = true)) }
                                }
                                raw.close()
                            }
                        }
                    }
                block(port)
                server.cancel()
            }
        } finally {
            udp.close()
            listener.close()
            selector.close()
        }
    }
}
