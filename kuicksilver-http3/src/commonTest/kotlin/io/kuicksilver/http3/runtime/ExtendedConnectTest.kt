// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.copyTo
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.message.CapsuleParser
import io.kuicksilver.http3.readAllBytes
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
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

internal fun connectReq(path: String = "/chat") = Http3Request("CONNECT", authority = "server.test", path = path)

private val connectOn = http3Settings { enableConnectProtocol = true }

class CapsuleParserTest {
    private fun capsule(
        type: Long,
        payload: ByteArray,
    ) = VarInt.encode(type) + VarInt.encode(payload.size.toLong()) + payload

    @Test fun datagramCapsule() {
        val got = ArrayList<Pair<Long, String>>()
        val p = CapsuleParser()
        val bytes = capsule(0x00, "hi".encodeToByteArray()) + capsule(0x00, "there".encodeToByteArray())
        for (b in bytes) p.feed(byteArrayOf(b), 0, 1) { t, payload -> got += t to payload.decodeToString() } // one byte at a time
        assertEquals(listOf(0L to "hi", 0L to "there"), got)
    }

    @Test fun unknownSkippedStreaming() {
        val got = ArrayList<Long>()
        val p = CapsuleParser()
        val header = VarInt.encode(0x2a) + VarInt.encode(1L shl 20)
        p.feed(header, 0, header.size) { t, _ -> got += t }
        val chunk = ByteArray(16_384)
        repeat(64) { p.feed(chunk, 0, chunk.size) { t, _ -> got += t } } // 1 MiB of an unknown capsule
        val next = capsule(0x00, byteArrayOf(7))
        p.feed(next, 0, next.size) { t, _ -> got += t }
        assertEquals(listOf(0L), got)
        assertTrue(p.maxBuffered <= 16_384 + 16)
    }

    @Test fun lengthAboveMaxRejected() {
        val p = CapsuleParser(maxCapsuleLength = 1000)
        val b = VarInt.encode(0x00) + VarInt.encode(1001)
        assertFailsWith<io.kuicksilver.http3.frame.H3ProtocolError> { p.feed(b, 0, b.size) { _, _ -> } }
    }
}

class ExtendedConnectTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun connectWaitsForPeerSettings() =
        h3Test {
            QuicPair.open().use { q ->
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
            H3Pair.open(serverSettings = connectOn).use { p ->
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
            H3Pair.open(serverSettings = connectOn).use { p ->
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
            H3Pair.open(serverSettings = connectOn).use { p ->
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
            H3Pair.open(serverSettings = connectOn).use { p ->
                launch {
                    val r = p.server.acceptRequest()
                    val s = r.acceptConnect(Http3Headers(listOf("sec-websocket-protocol" to "chat")))
                    assertEquals("v1, chat", s.headers["sec-websocket-protocol"])
                    s.output.flushAndClose()
                }
                val s =
                    p.client.connect(
                        Http3Request(
                            "CONNECT",
                            authority = "server.test",
                            path = "/chat",
                            headers =
                                Http3Headers(
                                    listOf("sec-websocket-protocol" to "v1, chat"),
                                ),
                        ),
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
                st.output.flush()
                assertEquals(
                    Http3ErrorCode.MESSAGE_ERROR,
                    assertFailsWith<QuicException.StreamError.Reset> { st.input.readAllBytes() }.code,
                )
            }
        }

    @Test fun rejectedConnectReportsStatus() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).use { p ->
                launch {
                    val w = p.server.acceptRequest().respond(501)
                    runCatching { w.finish() }
                } // the client may cancel on the 501 before the server's FIN
                assertEquals(501, assertFailsWith<Http3Exception.ConnectRejected> { p.client.connect(connectReq(), "unknown") }.status)
            }
        }
}

class H3DatagramTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun datagramsPerStream() =
        h3Test {
            H3Pair.open(serverSettings = connectOn).use { p ->
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

    @Test fun unknownStreamDroppedSilently() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                c.sendDatagram(VarInt.encode(100) + byteArrayOf(1, 2, 3))
                delay(300)
                assertFalse(server.closed.isCompleted)
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
                ).use { p ->
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
