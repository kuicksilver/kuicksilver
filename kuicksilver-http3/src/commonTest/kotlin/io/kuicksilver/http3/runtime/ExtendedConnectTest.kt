// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.DatagramUnsupportedReason
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal fun connectReq(path: String = "/chat") = http3Request("CONNECT", "server.test", path)

private val connectOn = http3Settings { enableConnectProtocol = true }

class ExtendedConnectTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun connectWaitsForPeerSettings() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                val stream = async { client.connect(connectReq(), "echo") }
                assertNull(withTimeoutOrNull(300.milliseconds) { s.acceptBidi() }) // nothing sent before the peer's SETTINGS
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L))
                val st = withTimeout(5.seconds) { s.acceptBidi() }
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flush()
                assertEquals(st.id, withTimeout(5.seconds) { stream.await() }.streamId)
            }
        }

    @Test fun connectWithoutSettingFails() =
        h3Test {
            H3Pair.open().use { p -> assertFailsWith<Http3Exception.Settings> { p.client.connect(connectReq(), "echo") } }
        }

    @Test fun bidirectionalEcho() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    assertEquals("echo", r.protocol)
                    assertEquals("CONNECT", r.method)
                    val s = r.acceptConnect()
                    s.input.copyTo(s.output)
                    s.output.flushAndClose()
                }
                val s = p.client.connect(connectReq(), "echo")
                val payload = ByteArray(1 shl 20) { it.toByte() }
                launch {
                    s.output.writeFully(payload)
                    s.output.flushAndClose()
                }
                assertContentEquals(payload, s.input.readAllBytes())
            }
        }

    /** The server closing its direction (FIN) leaves the client's direction open (RFC 9114 section 4.4). */
    @Test fun serverHalfCloseKeepsClientDirection() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                val got =
                    async {
                        val s = p.server.acceptRequest().acceptConnect()
                        s.output.writeFully("bye".encodeToByteArray())
                        s.output.flushAndClose()
                        s.input.readAllBytes().decodeToString()
                    }
                val s = p.client.connect(connectReq(), "echo")
                assertEquals("bye", s.input.readAllBytes().decodeToString())
                delay(100) // the server's FIN has been processed before the client answers
                s.output.writeFully("reply".encodeToByteArray())
                s.output.flushAndClose()
                assertEquals("reply", withTimeout(5.seconds) { got.await() })
            }
        }

    /** A tunnel that ended cleanly both ways releases its datagram registration on both sides. */
    @Test fun cleanEndUnregistersDatagrams() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch {
                    val s = p.server.acceptRequest().acceptConnect()
                    s.input.copyTo(s.output)
                    s.output.flushAndClose()
                }
                val s = p.client.connect(connectReq(), "echo")
                s.output.writeFully("x".encodeToByteArray())
                s.output.flushAndClose()
                assertEquals("x", s.input.readAllBytes().decodeToString())

                suspend fun registered(c: Http3Connection) =
                    kotlinx.coroutines.withContext(c.session.dispatcher) { c.session.datagrams.registeredCount }
                assertEquals(
                    true,
                    withTimeoutOrNull(3.seconds) {
                        while (registered(p.client) + registered(p.server) >
                            0
                        ) {
                            delay(10)
                        }
                        true
                    },
                    "client ${registered(p.client)}, server ${registered(p.server)} registrations left",
                )
            }
        }

    /** The 2xx's fields reach the client (e.g. `sec-websocket-protocol`, RFC 9220 section 3); found by the vendored Ktor contract. */
    @Test fun streamCarriesThePeersFields() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    val s = r.acceptConnect(Http3Headers(listOf("sec-websocket-protocol" to "chat")))
                    assertEquals("v1, chat", s.headers["sec-websocket-protocol"])
                    s.output.flushAndClose()
                }
                val s =
                    p.client.connect(
                        http3Request("CONNECT", "server.test", "/chat") {
                            headers =
                                Http3Headers(
                                    listOf("sec-websocket-protocol" to "v1, chat"),
                                )
                        },
                        "echo",
                    )
                assertEquals("chat", s.headers["sec-websocket-protocol"])
                s.output.flushAndClose()
            }
        }

    @Test fun protocolWithoutSettingIsMessageError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(
                    raw.headers(
                        st.id,
                        listOf(
                            ":method" to "CONNECT",
                            ":protocol" to "websocket",
                            ":scheme" to "https",
                            ":authority" to "a",
                            ":path" to "/",
                        ),
                    ),
                )
                peerMayHaveClosed { st.output.flush() }
                assertEquals(
                    Http3ErrorCode.MESSAGE_ERROR,
                    assertFailsWith<QuicException.StreamError.Reset> { st.input.readAllBytes() }.code,
                )
            }
        }

    /**
     * RFC 9114 section 4.4: once CONNECT completed only DATA may follow; any other known frame (HEADERS) is a connection
     * error H3_FRAME_UNEXPECTED. Before, the server took it as the request's trailers and ended the tunnel's input.
     */
    @Test fun headersOnEstablishedTunnelIsFrameUnexpectedOnServer() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, connectOn)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val req =
                    listOf(
                        ":method" to "CONNECT",
                        ":protocol" to "websocket",
                        ":scheme" to "https",
                        ":authority" to "a",
                        ":path" to "/ws",
                    )
                st.output.writeFully(raw.headers(st.id, req) + raw.data("hello".encodeToByteArray()))
                st.output.flush()
                val tunnel = server.acceptRequest().acceptConnect()
                launch { runCatching { tunnel.input.readAllBytes() } }
                // the 2xx arrived: the tunnel is established
                val head = ByteArray(1)
                st.input.readAvailable(head, 0, 1)
                peerMayHaveClosed {
                    st.output.writeFully(raw.headers(st.id, listOf("x-after" to "tunnel")))
                    st.output.flush()
                }
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, withTimeout(5.seconds) { peerSawClose(c) })
            }
        }

    /** The client side of the same rule: HEADERS from the server after its 2xx closes the connection with H3_FRAME_UNEXPECTED. */
    @Test fun headersOnEstablishedTunnelIsFrameUnexpectedOnClient() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L))
                launch {
                    val st = s.acceptBidi()
                    peerMayHaveClosed {
                        st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")) + raw.data("hi".encodeToByteArray()))
                        st.output.flush()
                        st.output.writeFully(raw.headers(st.id, listOf("x-after" to "tunnel")))
                        st.output.flush()
                    }
                }
                val stream = client.connect(connectReq(), "websocket")
                runCatching { stream.input.readAllBytes() }
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, withTimeout(5.seconds) { peerSawClose(s) })
            }
        }

    @Test fun rejectedConnectReportsStatus() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                launch {
                    val w = p.server.acceptRequest().respond(501)
                    runCatching { w.finish() }
                } // the client may cancel on the 501 before the server's FIN
                assertEquals(501, assertFailsWith<Http3Exception.ConnectRejected> { p.client.connect(connectReq(), "unknown") }.status)
            }
        }

    /**
     * RFC 9110 section 9.3.6: a CONNECT request has no content, and what follows its header section is the tunnel; per
     * RFC 9114 section 4.1.2 its `content-length` then does not describe the DATA frames. A CONNECT (classic and
     * Extended) declaring `content-length: 0` delivers its tunnel bytes instead of failing with H3_MESSAGE_ERROR.
     */
    @Test fun connectContentLengthDoesNotLimitTheTunnel() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, connectOn)
                val raw = RawPeer(c)
                raw.openControl()
                val classic = listOf(":method" to "CONNECT", ":authority" to "server.test:443", "content-length" to "0")
                val extended =
                    listOf(
                        ":method" to "CONNECT",
                        ":protocol" to "websocket",
                        ":scheme" to "https",
                        ":authority" to "a",
                        ":path" to "/ws",
                        "content-length" to "0",
                    )
                for (req in listOf(classic, extended)) {
                    val st = c.openBidi()
                    st.output.writeFully(raw.headers(st.id, req) + raw.data("hello".encodeToByteArray()))
                    st.output.flushAndClose()
                    val tunnel = server.acceptRequest().acceptConnect()
                    assertContentEquals("hello".encodeToByteArray(), withTimeout(5.seconds) { tunnel.input.readAllBytes() })
                }
            }
        }
}

class H3DatagramTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun datagramsPerStream() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                p.client.peerSettings
                    .filterNotNull()
                    .first()
                launch {
                    repeat(2) {
                        val r = p.server.acceptRequest()
                        launch {
                            val s = r.acceptConnect()
                            s.datagrams.take(3).collect {
                                s.sendDatagram(r.path!!.encodeToByteArray() + it)
                            }
                        }
                    }
                }
                val a = p.client.connect(connectReq("/a"), "echo")
                val b = p.client.connect(connectReq("/b"), "echo")
                delay(100)
                val gotA =
                    async {
                        a.datagrams
                            .take(3)
                            .toList()
                            .map { it.decodeToString() }
                    }
                val gotB =
                    async {
                        b.datagrams
                            .take(3)
                            .toList()
                            .map { it.decodeToString() }
                    }
                repeat(3) {
                    assertEquals(DatagramSendResult.Sent, a.trySendDatagram("x$it".encodeToByteArray()))
                    assertEquals(DatagramSendResult.Sent, b.trySendDatagram("y$it".encodeToByteArray()))
                }
                assertEquals(listOf("/ax0", "/ax1", "/ax2"), withTimeout(5.seconds) { gotA.await() }.sorted())
                assertEquals(listOf("/by0", "/by1", "/by2"), withTimeout(5.seconds) { gotB.await() }.sorted())
            }
        }

    /**
     * RFC 9297 section 2.1: "If a datagram is received after the corresponding stream's receive side is closed, the
     * received datagrams MUST be silently dropped": the stream's datagram flow ends with its receive side.
     */
    @Test fun datagramsAfterReceiveSideClosedAreDropped() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, connectOn)
                val raw = RawPeer(c)
                raw.openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                withTimeout(5.seconds) { server.peerSettings.filterNotNull().first() }
                val st = c.openBidi()
                val req = listOf(":method" to "CONNECT", ":protocol" to "echo", ":scheme" to "https", ":authority" to "a", ":path" to "/d")
                st.output.writeFully(raw.headers(st.id, req))
                st.output.flush()
                val tunnel = server.acceptRequest().acceptConnect()
                val got = kotlinx.coroutines.flow.MutableStateFlow(listOf<String>())
                val collector = launch { tunnel.datagrams.collect { d -> got.value = got.value + d.decodeToString() } }
                val quarter = VarInt.encode(st.id / 4)
                c.sendDatagram(quarter + "a".encodeToByteArray())
                withTimeout(5.seconds) { got.first { it == listOf("a") } }
                st.output.flushAndClose() // the receive side of the server's stream ends
                tunnel.input.readAllBytes()
                withTimeout(5.seconds) { collector.join() } // the flow ended with the receive side
                c.sendDatagram(quarter + "b".encodeToByteArray())
                delay(100)
                assertEquals(listOf("a"), got.value)
                assertFalse(server.closed.isCompleted)
            }
        }

    /**
     * RFC 9297 section 2.1: "HTTP/3 Datagrams MUST NOT be sent unless the corresponding stream's send side is open": once
     * our output is closed or the stream reset, trySendDatagram answers Closed and sendDatagram throws.
     */
    @Test fun noDatagramsAfterSendSideClosed() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).useScoped { p ->
                p.client.peerSettings
                    .filterNotNull()
                    .first()
                val serverSide = async { p.server.acceptRequest().acceptConnect() }
                val s = p.client.connect(connectReq(), "echo")
                assertEquals(DatagramSendResult.Sent, s.trySendDatagram(byteArrayOf(1)))
                s.output.flushAndClose()
                assertEquals(DatagramSendResult.Closed, s.trySendDatagram(byteArrayOf(2)))
                assertFailsWith<IllegalStateException> { s.sendDatagram(byteArrayOf(3)) }
                val t = serverSide.await()
                assertEquals(DatagramSendResult.Sent, t.trySendDatagram(byteArrayOf(4)))
                t.reset(Http3ErrorCode.REQUEST_CANCELLED)
                assertEquals(DatagramSendResult.Closed, t.trySendDatagram(byteArrayOf(5)))
            }
        }

    /**
     * RFC 9297 section 2.1: a datagram for a stream "that has not yet been created" is dropped silently (or buffered); one
     * within the stream limit here (stream 200, the 51st of 100; stream 400, the 101st, lies beyond it, see below).
     */
    @Test fun unknownStreamDroppedSilently() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                c.sendDatagram(VarInt.encode(50) + byteArrayOf(1, 2, 3))
                delay(300)
                assertFalse(server.closed.isCompleted)
            }
        }

    /**
     * RFC 9297 section 2.1: a datagram whose stream "cannot be created due to client-initiated bidirectional stream limits
     * ... SHOULD be treated as an HTTP/3 connection error of type H3_ID_ERROR". The server granted 10 streams: stream 40 is
     * the eleventh.
     */
    @Test fun negative_datagramBeyondTheStreamLimitIsIdErrorOnTheServer() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxBidiStreams = 10 }).use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                c.sendDatagram(VarInt.encode(10) + byteArrayOf(1))
                assertEquals(Http3ErrorCode.ID_ERROR, withTimeout(5.seconds) { peerSawClose(c) })
                assertEquals(Http3ErrorCode.ID_ERROR, assertIs<Http3Exception.Protocol>(server.closed.await()).h3Code)
            }
        }

    /** The client's mirror: the server allowed it 10 streams, so a datagram for stream 40 names no request it could make. */
    @Test fun negative_datagramBeyondTheStreamLimitIsIdErrorOnTheClient() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxBidiStreams = 10 }).use { q ->
                val (c, s) = q.connect()
                RawPeer(s).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                val client = Http3Connection.client(c)
                withTimeout(5.seconds) { client.peerSettings.filterNotNull().first() }
                s.sendDatagram(VarInt.encode(10) + byteArrayOf(1))
                assertEquals(Http3ErrorCode.ID_ERROR, withTimeout(5.seconds) { peerSawClose(s) })
            }
        }

    @Test fun truncatedQuarterIdIsDatagramError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                c.sendDatagram(byteArrayOf(0x40)) // a 2-byte varint cut after its first byte
                assertEquals(Http3ErrorCode.DATAGRAM_ERROR, peerSawClose(c))
            }
        }

    @Test fun h3DatagramWithoutTransportIsSettingsError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect(clientQuic = quicConfig { maxDatagramFrameSize = 0 })
                Http3Connection.server(s)
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                assertEquals(Http3ErrorCode.SETTINGS_ERROR, peerSawClose(c))
            }
        }

    @Test fun unsupportedUntilBothSettings() =
        h3Test {
            H3Pair
                .open(
                    serverSettings =
                        http3Settings {
                            enableConnectProtocol = true
                            h3Datagram = false
                        },
                ).useScoped { p ->
                    launch { p.server.acceptRequest().acceptConnect() }
                    val s = p.client.connect(connectReq(), "echo")
                    assertEquals(
                        DatagramSendResult.Unsupported(DatagramUnsupportedReason.PeerDoesNotSupport),
                        s.trySendDatagram(byteArrayOf(1)),
                    )
                }
        }

    @Test fun h3DatagramSettingAlwaysSent() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s, http3Settings { h3Datagram = false })
                val control =
                    withTimeout(5.seconds) {
                        while (true) {
                            val st = c.acceptStream()
                            if (st.readVarInt() ==
                                StreamType.CONTROL
                            ) {
                                return@withTimeout st
                            }
                        }
                        @Suppress("UNREACHABLE_CODE")
                        null!!
                    }
                val (t, payload) = control.readControlFrame()
                assertEquals(FrameType.SETTINGS, t)
                assertEquals(0L, SettingsCodec.decode(payload)[SettingsId.H3_DATAGRAM])
            }
        }
}
