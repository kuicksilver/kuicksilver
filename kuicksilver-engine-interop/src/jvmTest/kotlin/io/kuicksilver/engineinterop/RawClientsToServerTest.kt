// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.future.await
import kotlinx.coroutines.withTimeout
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.util.UUID
import java.util.concurrent.CompletionStage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * OkHttp 5 and the JDK's java.net.http client on their own APIs (not through Ktor) against our server: what Ktor's client
 * API hides — the protocol ALPN chose with HTTP/2 on and off at the server, OkHttp's own permessage-deflate, the JDK's
 * WebSocket fragments, Ping and Pong, and close codes. HTTP/3: neither client has it (the JDK's arrives in JDK 26, JEP
 * 517; the toolchain here is 21).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal class RawClientsToServerTest {
    private lateinit var h2Server: RunningServer
    private lateinit var h1Server: RunningServer
    private lateinit var deflateServer: RunningServer

    @BeforeAll fun start() {
        h2Server = startServer(ServerEngine.Kuicksilver, tls = true, http2 = true)
        h1Server = startServer(ServerEngine.Kuicksilver, tls = true, http2 = false)
        deflateServer = startServer(ServerEngine.Kuicksilver, tls = true, http2 = true, deflate = true)
    }

    @AfterAll fun stop() {
        h2Server.close()
        h1Server.close()
        deflateServer.close()
    }

    private fun okHttp(vararg protocols: Protocol): OkHttpClient =
        OkHttpClient
            .Builder()
            .sslSocketFactory(Pki.clientContext().socketFactory, Pki.trustManager())
            .protocols(protocols.toList())
            .build()

    private fun OkHttpClient.shutdown() {
        dispatcher.executorService.shutdown()
        connectionPool.evictAll()
    }

    private fun jdk(version: HttpClient.Version): HttpClient =
        HttpClient
            .newBuilder()
            .sslContext(Pki.clientContext())
            .version(version)
            .build()

    /**
     * ALPN (RFC 7301 section 3.2; RFC 9113 section 3.2): a server with HTTP/2 on picks `h2` from OkHttp's offer, one with
     * HTTP/2 off picks `http/1.1` from the same offer, and a client offering only `http/1.1` gets it.
     */
    @Test fun okHttpAlpn() {
        val both = okHttp(Protocol.HTTP_2, Protocol.HTTP_1_1)
        val h1Only = okHttp(Protocol.HTTP_1_1)
        try {
            fun get(
                c: OkHttpClient,
                s: RunningServer,
            ): Response = c.newCall(Request.Builder().url(s.url("/version")).build()).execute()
            get(both, h2Server).use {
                assertEquals(Protocol.HTTP_2, it.protocol)
                assertEquals("HTTP/2", it.body.string())
            }
            get(both, h1Server).use { assertEquals(Protocol.HTTP_1_1, it.protocol) }
            get(h1Only, h2Server).use {
                assertEquals(Protocol.HTTP_1_1, it.protocol)
                assertEquals("HTTP/1.1", it.body.string())
            }
        } finally {
            both.shutdown()
            h1Only.shutdown()
        }
    }

    /** The JDK client: `h2` when both offer it, HTTP/1.1 from a server with HTTP/2 off or a client asking for HTTP/1.1. */
    @Test fun jdkAlpn() =
        interopTest {
            jdk(HttpClient.Version.HTTP_2).use { c ->
                val r =
                    c
                        .sendAsync(
                            HttpRequest.newBuilder(URI(h2Server.url("/version"))).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        ).await()
                assertEquals(HttpClient.Version.HTTP_2, r.version())
                assertEquals("HTTP/2", r.body())
                val r1 =
                    c
                        .sendAsync(
                            HttpRequest.newBuilder(URI(h1Server.url("/version"))).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        ).await()
                assertEquals(HttpClient.Version.HTTP_1_1, r1.version())
            }
            jdk(HttpClient.Version.HTTP_1_1).use { c ->
                val r =
                    c
                        .sendAsync(
                            HttpRequest.newBuilder(URI(h2Server.url("/version"))).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        ).await()
                assertEquals(HttpClient.Version.HTTP_1_1, r.version())
            }
        }

    /** OkHttp's WebSocket events, as deferreds and a queue. */
    private class OkListener : WebSocketListener() {
        val opened = CompletableDeferred<Response>()
        val messages = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        val closing = CompletableDeferred<Pair<Int, String>>()
        val failure = CompletableDeferred<Throwable>()

        override fun onOpen(
            webSocket: WebSocket,
            response: Response,
        ) {
            opened.complete(response)
        }

        override fun onMessage(
            webSocket: WebSocket,
            text: String,
        ) {
            messages.trySend(text)
        }

        override fun onMessage(
            webSocket: WebSocket,
            bytes: ByteString,
        ) {
            messages.trySend("bytes:${bytes.size}")
        }

        override fun onClosing(
            webSocket: WebSocket,
            code: Int,
            reason: String,
        ) {
            closing.complete(code to reason)
            webSocket.close(code, null)
        }

        override fun onFailure(
            webSocket: WebSocket,
            t: Throwable,
            response: Response?,
        ) {
            failure.complete(t)
            opened.completeExceptionally(t)
        }
    }

    /**
     * OkHttp offers permessage-deflate on every WebSocket (RFC 7692); our server with PerMessageDeflate accepts it, and
     * compressible messages go both ways in the shared window, a large one first and small ones after (section 7.1.1).
     */
    @Test fun okHttpWebSocketPermessageDeflate() =
        interopTest {
            val c = okHttp(Protocol.HTTP_1_1)
            try {
                val l = OkListener()
                val ws = c.newWebSocket(Request.Builder().url(deflateServer.wsUrl("/ws/echo")).build(), l)
                val response = withTimeout(10.seconds) { l.opened.await() }
                val ext = response.header("Sec-WebSocket-Extensions")
                assertNotNull(ext)
                assertTrue(ext.startsWith("permessage-deflate"), ext)
                val big = "compressible ".repeat(5000)
                repeat(3) { i ->
                    ws.send(big)
                    assertEquals(big, withTimeout(10.seconds) { l.messages.receive() })
                    ws.send("small $i")
                    assertEquals("small $i", withTimeout(10.seconds) { l.messages.receive() })
                }
                ws.send(ByteString.of(*ByteArray(70_000) { 1 }))
                assertEquals("bytes:70000", withTimeout(10.seconds) { l.messages.receive() })
                ws.close(1000, null)
            } finally {
                c.shutdown()
            }
        }

    /** OkHttp reads the server's close code and reason (RFC 6455 section 7.1.5 and 7.1.6). */
    @Test fun okHttpWebSocketServerClose() =
        interopTest {
            val c = okHttp(Protocol.HTTP_1_1)
            try {
                val l = OkListener()
                c.newWebSocket(Request.Builder().url(h2Server.wsUrl("/ws/close?code=4001&reason=server%20bye")).build(), l)
                assertEquals(4001 to "server bye", withTimeout(10.seconds) { l.closing.await() })
            } finally {
                c.shutdown()
            }
        }

    /** OkHttp's close code and reason reach the server's application. */
    @Test fun okHttpWebSocketClientClose() =
        interopTest {
            val c = okHttp(Protocol.HTTP_1_1)
            try {
                val id = UUID.randomUUID().toString()
                val l = OkListener()
                val ws = c.newWebSocket(Request.Builder().url(h2Server.wsUrl("/ws/client-close/$id")).build(), l)
                withTimeout(10.seconds) { l.opened.await() }
                ws.close(4002, "client bye")
                val reason = withTimeout(10.seconds) { h2Server.probe.closeOf(id).await() }
                assertEquals(4002.toShort(), reason?.code)
                assertEquals("client bye", reason?.message)
            } finally {
                c.shutdown()
            }
        }

    /** The JDK's WebSocket events. */
    private class JdkListener : java.net.http.WebSocket.Listener {
        val text = StringBuilder()
        val messages = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        val pongs = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        val closed = CompletableDeferred<Pair<Int, String>>()

        override fun onText(
            webSocket: java.net.http.WebSocket,
            data: CharSequence,
            last: Boolean,
        ): CompletionStage<*>? {
            text.append(data)
            if (last) {
                messages.trySend(text.toString())
                text.clear()
            }
            webSocket.request(1)
            return null
        }

        override fun onPong(
            webSocket: java.net.http.WebSocket,
            message: ByteBuffer,
        ): CompletionStage<*>? {
            val b = ByteArray(message.remaining()).also { message.get(it) }
            pongs.trySend(b.decodeToString())
            webSocket.request(1)
            return null
        }

        override fun onClose(
            webSocket: java.net.http.WebSocket,
            statusCode: Int,
            reason: String,
        ): CompletionStage<*>? {
            closed.complete(statusCode to reason)
            return null
        }
    }

    private suspend fun jdkWebSocket(
        c: HttpClient,
        url: String,
        l: JdkListener,
    ): java.net.http.WebSocket =
        c
            .newWebSocketBuilder()
            .buildAsync(URI(url), l)
            .await()

    /**
     * The JDK sends a text message in fragments (sendText with last = false, RFC 6455 section 5.4): the application of our
     * server reads one 3000-character message (our engine hands it whole).
     */
    @Test fun jdkWebSocketFragmentsReachTheServerAsOneMessage() =
        interopTest {
            jdk(HttpClient.Version.HTTP_1_1).use { c ->
                val l = JdkListener()
                val ws = jdkWebSocket(c, h2Server.wsUrl("/ws/assemble"), l)
                ws.sendText("a".repeat(1000), false).await()
                ws.sendText("b".repeat(1000), false).await()
                ws.sendText("c".repeat(1000), true).await()
                assertTrue(withTimeout(10.seconds) { l.messages.receive() }.startsWith("3000:"))
                ws.abort() // the server ends the session after its answer
            }
        }

    /** RFC 6455 section 5.5.3: our server answers the JDK's Ping with a Pong carrying the same application data. */
    @Test fun jdkWebSocketPingGetsPong() =
        interopTest {
            jdk(HttpClient.Version.HTTP_1_1).use { c ->
                val l = JdkListener()
                val ws = jdkWebSocket(c, h2Server.wsUrl("/ws/echo"), l)
                ws.sendPing(ByteBuffer.wrap("are you there".encodeToByteArray())).await()
                assertEquals("are you there", withTimeout(10.seconds) { l.pongs.receive() })
                ws.sendText("still open", true).await()
                assertEquals("still open", withTimeout(10.seconds) { l.messages.receive() })
                ws.sendClose(1000, "").await()
            }
        }

    /** Close codes both ways with the JDK client (RFC 6455 section 7.4). */
    @Test fun jdkWebSocketCloseCodes() =
        interopTest {
            jdk(HttpClient.Version.HTTP_1_1).use { c ->
                val l = JdkListener()
                jdkWebSocket(c, h2Server.wsUrl("/ws/close?code=4001&reason=server%20bye"), l)
                assertEquals(4001 to "server bye", withTimeout(10.seconds) { l.closed.await() })
                val id = UUID.randomUUID().toString()
                val ws = jdkWebSocket(c, h2Server.wsUrl("/ws/client-close/$id"), JdkListener())
                ws.sendClose(4002, "client bye").await()
                val reason = withTimeout(10.seconds) { h2Server.probe.closeOf(id).await() }
                assertEquals(4002.toShort(), reason?.code)
                assertEquals("client bye", reason?.message)
            }
        }

    /**
     * The JDK client's HTTP/2 requests are multiplexed on one connection: once a first request has established it, 20 at
     * once share its client port.
     */
    @Test fun jdkH2Multiplexing() =
        interopTest {
            jdk(HttpClient.Version.HTTP_2).use { c ->
                val first =
                    c
                        .sendAsync(
                            HttpRequest.newBuilder(URI(h2Server.url("/peer"))).build(),
                            HttpResponse.BodyHandlers.ofString(),
                        ).await()
                val all =
                    (1..20)
                        .map {
                            c.sendAsync(
                                HttpRequest.newBuilder(URI(h2Server.url("/peer"))).build(),
                                HttpResponse.BodyHandlers.ofString(),
                            )
                        }.map { it.await() }
                assertTrue(all.all { it.version() == HttpClient.Version.HTTP_2 })
                assertEquals(setOf(first.body()), all.map { it.body() }.toSet())
            }
        }
}
