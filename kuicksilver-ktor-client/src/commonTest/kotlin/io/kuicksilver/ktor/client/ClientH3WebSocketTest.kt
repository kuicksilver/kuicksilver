// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** How an HTTP/3 WebSocket session ends (RFC 9220), the same with Ktor's JVM and common (Native) WebSocket readers. */
class ClientH3WebSocketTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The server's FIN can trail its Close frame (the core sends a flushed frame at once, the FIN with the close): a client
     * whose closing handshake ends before that FIN arrives still delivers its Close reply and FIN, and abandons only the
     * read side (STOP_SENDING), never its own finished send side (RESET_STREAM). Ordered here by holding the FIN back.
     * On every platform: Ktor's JVM WebSocket reader stops at the Close frame, and the engine ends the stream it hands to the
     * common (Native) reader after the peer's Close frame too, so a session never waits for a FIN that does not come.
     */
    @Test fun webSocketClosedBeforeThePeersFinKeepsItsCloseReply() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity =
                        TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(serverTls).build()
                        }.build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            val clientDone = CompletableDeferred<Unit>()
            coroutineScope {
                val served =
                    async {
                        val conn = ep.accept()
                        val s = conn.acceptRequest().acceptConnect()
                        s.output.writeFully(byteArrayOf(0x88.toByte(), 0x02, 0x03, 0xE8.toByte()))
                        s.output.flush() // Close(1000) without FIN: the FIN follows only after the client's call is over
                        clientDone.await()
                        val read =
                            runCatching {
                                s.input
                                    .readRemaining()
                                    .readByteArray()
                                    .size
                            }
                        runCatching { s.output.flushAndClose() }
                        read
                    }
                try {
                    testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                        // the session ends on the Close exchange, not on the FIN
                        withTimeout(10.seconds) { c.webSocket("wss://127.0.0.1:${ep.localAddress.port}/ws") { for (f in incoming) Unit } }
                        clientDone.complete(Unit)
                        val got = withTimeout(5.seconds) { served.await() }
                        assertTrue(got.isSuccess && got.getOrThrow() >= 6, "the server reads the client's Close reply and FIN, got $got")
                    }
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /**
     * A call that ends with a cause after its session sent the Close frame and finished its send side (the caller is
     * cancelled during the closing handshake) does not reset the HTTP/3 stream: the Close and the FIN still in flight
     * reach the peer, not a reset. The relay holds the client's packets until the call has ended, so the Close is still
     * unacknowledged when the call ends; before, the engine reset the send side then and the peer never got the Close.
     */
    @Test fun closeSentBeforeACancelledCallIsNotReset() =
        h3Test {
            val serverTls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf("h3")
                    identity =
                        TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                }
            val ep =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(serverTls).build()
                        }.build(),
                    io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
                )
            coroutineScope {
                // the close code of the client's first frame, or -2 when its send side then ends in a reset, not a FIN
                val served =
                    async {
                        val conn = ep.accept()
                        val s = conn.acceptRequest().acceptConnect()
                        val code = closeCodeOfFirstFrame(s.input)
                        if (runCatching { s.input.readRemaining() }.isFailure) -2 else code
                    }
                try {
                    udpRelay(ep.localAddress.port) { relayPort, relay ->
                        testClient(Http3DiscoveryMode.H3Only, block = { install(WebSockets) }).use { c ->
                            val closeSent = CompletableDeferred<Unit>()
                            coroutineScope {
                                val call =
                                    launch {
                                        c.webSocket("wss://127.0.0.1:$relayPort/ws") {
                                            relay.blocked = true
                                            close(CloseReason(CloseReason.Codes.GOING_AWAY, "bye"))
                                            flush() // returns once the writer wrote the Close and finished the send side
                                            closeSent.complete(Unit)
                                            awaitCancellation()
                                        }
                                    }
                                withTimeout(10.seconds) { closeSent.await() }
                                call.cancel()
                                call.join()
                            }
                            relay.blocked = false
                            assertEquals(1001, withTimeout(10.seconds) { served.await() })
                        }
                    }
                } finally {
                    served.cancel()
                    ep.close()
                }
            }
        }

    /** The close code of the first frame on [input] (a Close frame, masked or not), or -1 for anything else. */
    private suspend fun closeCodeOfFirstFrame(input: ByteReadChannel): Int =
        runCatching {
            val b0 = input.readByte().toInt() and 0xff
            val b1 = input.readByte().toInt() and 0xff
            val length = b1 and 0x7f // a Close frame's payload is at most 125 bytes
            val mask = if (b1 and 0x80 != 0) input.readByteArray(4) else ByteArray(4)
            val payload = input.readByteArray(length).mapIndexed { i, b -> (b.toInt() xor mask[i % 4].toInt()) and 0xff }
            if (b0 and 0x0f != 0x8 || payload.size < 2) -1 else (payload[0] shl 8) or payload[1]
        }.getOrDefault(-1)
}
