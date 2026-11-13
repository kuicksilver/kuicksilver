// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.client.HttpClient
import io.ktor.client.plugins.websocket.DefaultClientWebSocketSession
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readBytes
import io.ktor.websocket.readText
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.util.UUID
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * WebSockets over HTTP/1.1 (RFC 6455) between one Ktor client engine and one Ktor server engine, one of them Kuicksilver's:
 * text, binary and fragmented messages both ways, Ping and Pong, close codes both ways, and permessage-deflate (RFC 7692)
 * where the client engine negotiates extensions. Each subclass is one pair.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal abstract class WebSocketPairSuite(
    private val serverEngine: ServerEngine,
    private val clientEngine: ClientEngine,
    private val tls: Boolean,
) {
    protected lateinit var server: RunningServer
    protected lateinit var client: HttpClient

    @BeforeAll fun startPair() {
        server = startServer(serverEngine, tls = tls)
        client = ktorClient(clientEngine, http2 = false)
    }

    @AfterAll fun stopPair() {
        client.close()
        server.close()
    }

    protected suspend fun <T> session(
        path: String,
        c: HttpClient = client,
        s: RunningServer = server,
        block: suspend DefaultClientWebSocketSession.() -> T,
    ): T {
        val session = c.webSocketSession(s.wsUrl(path))
        try {
            return session.block()
        } finally {
            session.close()
        }
    }

    /** The next data frame's text (a message may arrive in fragments: they are joined until FIN, RFC 6455 section 5.4). */
    protected suspend fun DefaultClientWebSocketSession.receiveMessage(): String {
        val out = StringBuilder()
        while (true) {
            val f = withTimeout(10.seconds) { incoming.receive() }
            if (f !is Frame.Text) continue
            out.append(f.readText())
            if (f.fin) return out.toString()
        }
    }

    @Test fun textEcho() =
        interopTest {
            session("/ws/echo") {
                send(Frame.Text("hello, ✓ — привет"))
                assertEquals("hello, ✓ — привет", receiveMessage())
            }
        }

    /** A 256 KiB binary message (64-bit payload length, RFC 6455 section 5.2) and an empty one. */
    @Test fun binaryEcho() =
        interopTest {
            val data = Random(4).nextBytes(256 * 1024)
            session("/ws/echo") {
                send(Frame.Binary(true, data))
                val back = withTimeout(10.seconds) { incoming.receive() }
                assertTrue(back is Frame.Binary)
                val bytes = ArrayList<Byte>()
                var frame: Frame = back
                while (true) {
                    bytes.addAll(frame.readBytes().toList())
                    if (frame.fin) break
                    frame = withTimeout(10.seconds) { incoming.receive() }
                }
                assertContentEquals(data, bytes.toByteArray())
                send(Frame.Binary(true, ByteArray(0)))
                assertEquals(0, (withTimeout(10.seconds) { incoming.receive() } as Frame.Binary).readBytes().size)
            }
        }

    /**
     * The client sends one text message in three fragments (RFC 6455 section 5.4): the server reads one message of the
     * whole length, whatever fragments its engine hands the application.
     */
    @Test open fun clientFragmentedMessage() =
        interopTest {
            session("/ws/assemble") {
                send(Frame.Text(false, "a".repeat(1000).encodeToByteArray()))
                send(Frame.Text(false, "b".repeat(1000).encodeToByteArray()))
                send(Frame.Text(true, "c".repeat(1000).encodeToByteArray()))
                val answer = receiveMessage().split(":")
                assertEquals("3000", answer[0], "the length the server reassembled: $answer")
            }
        }

    /** The server sends one message in three fragments: the client reads "fragmented". */
    @Test fun serverFragmentedMessage() =
        interopTest {
            session("/ws/fragments") { assertEquals("fragmented", receiveMessage()) }
        }

    /** RFC 6455 section 5.5.2: "Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in response", with the Ping's data (5.5.3). */
    @Test fun serverPingGetsPong() =
        interopTest {
            session("/ws/ping?n=7") { assertEquals("pong:ping-7", receiveMessage()) }
        }

    /** RFC 6455 section 7.4: the server's close code and reason reach the client unchanged. */
    @Test fun serverCloseCodeAndReason() =
        interopTest {
            val s = client.webSocketSession(server.wsUrl("/ws/close?code=4001&reason=server%20bye"))
            val reason = withTimeout(10.seconds) { s.closeReason.await() }
            assertEquals(CloseReason(4001, "server bye"), reason)
        }

    /** The client's close code and reason reach the server's application unchanged. */
    @Test fun clientCloseCodeAndReason() =
        interopTest {
            val id = UUID.randomUUID().toString()
            val s = client.webSocketSession(server.wsUrl("/ws/client-close/$id"))
            s.close(CloseReason(4002, "client bye"))
            val reason = withTimeout(10.seconds) { server.probe.closeOf(id).await() }
            assertEquals(CloseReason(4002, "client bye"), reason)
        }

    /**
     * permessage-deflate (RFC 7692): a client engine that negotiates extensions offers it and the server accepts it
     * (section 5: the answer's Sec-WebSocket-Extensions names it); compressible and small messages go both ways, one after
     * the other in the same window (context takeover, section 7.1.1). Ours is PerMessageDeflate, Ktor's engines use Ktor's
     * WebSocketDeflateExtension.
     */
    @Test fun permessageDeflate() =
        interopTest {
            if (!clientEngine.wsExtensions) return@interopTest
            startServer(serverEngine, tls = tls, deflate = true).use { s ->
                ktorClient(clientEngine, http2 = false, deflate = true).use { c ->
                    session("/ws/echo", c, s) {
                        val negotiated = call.response.headers["Sec-WebSocket-Extensions"]
                        assertNotNull(negotiated)
                        assertTrue(negotiated.startsWith("permessage-deflate"), negotiated)
                        val big = "compressible text ".repeat(4000)
                        repeat(3) {
                            send(Frame.Text(big))
                            assertEquals(big, receiveMessage())
                            send(Frame.Text("small $it"))
                            assertEquals("small $it", receiveMessage())
                        }
                    }
                }
            }
        }
}

/** Our client, Ktor Netty server, wss:// (HTTP/1.1 over TLS). */
internal class ClientToNettyWebSocketTest : WebSocketPairSuite(ServerEngine.Netty, ClientEngine.Kuicksilver, tls = true)

/** Our client, Ktor CIO server, ws://. */
internal class ClientToCioWebSocketTest : WebSocketPairSuite(ServerEngine.Cio, ClientEngine.Kuicksilver, tls = false)

/** Ktor CIO client, our server, ws://. */
internal class CioToServerWebSocketTest : WebSocketPairSuite(ServerEngine.Kuicksilver, ClientEngine.Cio, tls = false)

/** Ktor OkHttp client, our server, wss://. */
internal class OkHttpToServerWebSocketTest : WebSocketPairSuite(ServerEngine.Kuicksilver, ClientEngine.OkHttp, tls = true) {
    /**
     * OkHttp's WebSocket has no fragments in its API and Ktor's OkHttp engine sends each Frame as a message of its own,
     * FIN set, whatever the frame's `fin` says: the server reads the first fragment as a whole message of 1000 characters
     * (one frame). Not an error on either side, but a fragmented message cannot be sent through that engine.
     */
    @Test override fun clientFragmentedMessage() =
        interopTest {
            session("/ws/assemble") {
                send(Frame.Text(false, "a".repeat(1000).encodeToByteArray()))
                send(Frame.Text(true, "b".repeat(1000).encodeToByteArray()))
                assertEquals("1000:1:aaaaaaaaaaaaaaaa", receiveMessage())
            }
        }
}

/** Ktor Java client, our server, wss://. */
internal class JavaToServerWebSocketTest : WebSocketPairSuite(ServerEngine.Kuicksilver, ClientEngine.Java, tls = true)
