// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.qpack.DecodeResult
import io.kuicksilver.http3.qpack.QpackDecoder
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.acceptBidi
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerMayHaveClosed
import io.kuicksilver.http3.runtime.readControlFrame
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

internal fun wtReq(
    path: String = "/wt",
    vararg fields: Pair<String, String>,
) = http3Request("CONNECT", "server.test", path) { headers = Http3Headers(fields.toList()) }

/** The fields of the next HEADERS frame on [st] (the peer's encoder uses the static table only). */
internal suspend fun readHeaders(st: QuicStream): Map<String, String> {
    val (t, payload) = withTimeout(5.seconds) { st.readControlFrame() }
    assertEquals(FrameType.HEADERS, t)
    val d = QpackDecoder(0, 0, 65_536).decode(st.id, payload)
    return (d as DecodeResult.Decoded).fields.toMap()
}

/** A WebTransport CONNECT from a raw client on a new stream. */
internal fun RawPeer.wtConnect(
    st: QuicStream,
    token: String = WtTokens.H3,
    vararg extra: Pair<String, String>,
): ByteArray =
    headers(
        st.id,
        listOf(":method" to "CONNECT", ":protocol" to token, ":scheme" to "https", ":authority" to "server.test", ":path" to "/wt") +
            extra,
    )

private val connectOnly = http3Settings { enableConnectProtocol = true }

class WebTransportSessionTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun establishDraft16() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch {
                    val r = p.server.acceptRequest()
                    assertTrue(r.isWebTransport)
                    assertEquals(WtTokens.H3, r.protocol)
                    serverSide.complete(r.acceptWebTransport())
                }
                val session = p.client.webTransport(wtReq(fields = arrayOf("origin" to "https://app.test")))
                assertEquals(0L, session.sessionId)
                assertNull(session.protocol)
                val s = withTimeout(5.seconds) { serverSide.await() }
                assertEquals(0L, s.sessionId)
                assertEquals("https://app.test", s.headers["origin"])
            }
        }

    /** Browsers send draft-02's token and field; the server answers 200 with the field Chrome checks. */
    @Test fun establishLegacyTokenAccepted() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                launch {
                    val r = server.acceptRequest()
                    assertTrue(r.isWebTransport)
                    r.acceptWebTransport()
                }
                val st = c.openBidi()
                st.output.writeFully(raw.wtConnect(st, WtTokens.LEGACY, WtTokens.DRAFT02_REQUEST_FIELD to "1"))
                st.output.flush()
                val h = readHeaders(st)
                assertEquals("200", h[":status"])
                assertEquals(WtTokens.DRAFT02_RESPONSE_VALUE, h[WtTokens.DRAFT02_RESPONSE_FIELD])
            }
        }

    @Test fun clientUsesLegacyTokenForDraft02Server() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(
                    listOf(
                        SettingsId.ENABLE_CONNECT_PROTOCOL to 1L,
                        SettingsId.H3_DATAGRAM to 1L,
                        SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L,
                    ),
                )
                val client = Http3Connection.client(c, wtOn)
                val session = async { client.webTransport(wtReq()) }
                val st = withTimeout(5.seconds) { s.acceptBidi() }
                val h = readHeaders(st)
                assertEquals(WtTokens.LEGACY, h[":protocol"])
                assertEquals("1", h[WtTokens.DRAFT02_REQUEST_FIELD])
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flush()
                assertEquals(st.id, withTimeout(5.seconds) { session.await() }.sessionId)
            }
        }

    /** Section 5.1: without flow control a connection has one session; a second CONNECT is refused before the application. */
    @Test fun negative_secondSessionRejected() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val accepted = CompletableDeferred<WebTransportSession>()
                launch { accepted.complete(server.acceptRequest().acceptWebTransport()) }
                val first = c.openBidi()
                first.output.writeFully(raw.wtConnect(first))
                first.output.flush()
                assertEquals("200", readHeaders(first)[":status"])
                withTimeout(5.seconds) { accepted.await() }
                val second = c.openBidi()
                peerMayHaveClosed {
                    second.output.writeFully(raw.wtConnect(second))
                    second.output.flush()
                }
                assertEquals(Http3ErrorCode.REQUEST_REJECTED, resetCode(second))
                // the first lives on: its streams still reach it
                raw.uni(StreamType.WT_UNI, VarInt.encode(first.id) + "still".encodeToByteArray(), fin = true)
                val st = withTimeout(5.seconds) { accepted.await().acceptUni() }
                assertEquals("still", st.input.readAllBytes().decodeToString())
                assertFalse(server.closed.isCompleted)
            }
        }

    @Test fun clientRefusesSecondSession() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val first = p.client.webTransport(wtReq())
                assertFailsWith<IllegalStateException> { p.client.webTransport(wtReq()) }
                // the first lives on: a stream the client opens for it reaches the server's session
                val uni = p.client.quic.openUni()
                uni.output.writeFully(VarInt.encode(StreamType.WT_UNI) + VarInt.encode(first.sessionId) + "alive".encodeToByteArray())
                uni.output.flushAndClose()
                val st = withTimeout(5.seconds) { serverSide.await().acceptUni() }
                assertEquals("alive", st.input.readAllBytes().decodeToString())
            }
        }

    /** A session whose CONNECT stream ended frees the connection's slot, and its late streams are rejected. */
    @Test fun endedSessionFreesTheSlot() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                launch {
                    repeat(2) {
                        val session = server.acceptRequest().acceptWebTransport() as WtSessionImpl
                        if (it == 0) session.capsules.close() // the server's side of the first session ends
                    }
                }
                val first = c.openBidi()
                first.output.writeFully(raw.wtConnect(first))
                first.output.flush()
                assertEquals("200", readHeaders(first)[":status"])
                first.output.flushAndClose()
                first.input.readAllBytes() // the server's FIN: both sides ended
                val second = c.openBidi()
                second.output.writeFully(raw.wtConnect(second))
                second.output.flush()
                assertEquals("200", readHeaders(second)[":status"])
                val late = c.wtBidi(first.id, fin = false)
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, resetCode(late))
            }
        }

    /**
     * The exchange's end can reach the session before its capsule reader read the peer's FIN (both are dispatched from the
     * same stream): the session then waits for the reader's verdict, a clean close with code 0 (section 6), and does not
     * reset the CONNECT stream, whose RESET_STREAM could overtake the FIN it already sent (RFC 9000 section 3.1).
     */
    @Test fun exchangeEndBeforeTheReaderSawFinIsACleanClose() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val accepted = CompletableDeferred<WtSessionImpl>()
                launch { accepted.complete(server.acceptRequest().acceptWebTransport() as WtSessionImpl) }
                val first = c.openBidi()
                first.output.writeFully(raw.wtConnect(first))
                first.output.flush()
                assertEquals("200", readHeaders(first)[":status"])
                val session = withTimeout(5.seconds) { accepted.await() }
                session.capsules.close() // the server's side ends
                withContext(server.session.dispatcher) { session.ended() } // ahead of the reader, as the race had it
                first.output.flushAndClose() // the client's FIN, no WT_CLOSE_SESSION
                val seen = withTimeout(5.seconds) { session.closed.await() }
                assertEquals(0L, seen.code)
                assertNull(seen.cause)
                assertEquals(0, withTimeout(5.seconds) { first.input.readAllBytes() }.size) // the server's FIN, not a reset
            }
        }

    @Test fun protocolNegotiated() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                launch {
                    val r = p.server.acceptRequest()
                    assertEquals(listOf("chat-v1", "chat-v2"), r.availableProtocols)
                    assertEquals("chat-v2", r.acceptWebTransport(protocol = "chat-v2").protocol)
                }
                assertEquals("chat-v2", p.client.webTransport(wtReq(), listOf("chat-v1", "chat-v2")).protocol)
            }
        }

    @Test fun serverRefusesProtocolNotOffered() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val refused = CompletableDeferred<Throwable>()
                launch {
                    val r = p.server.acceptRequest()
                    refused.complete(assertFailsWith<IllegalArgumentException> { r.acceptWebTransport(protocol = "other") })
                    runCatching { r.respond(400).finish() } // the client may cancel on the 400 before our FIN
                }
                assertEquals(400, assertFailsWith<Http3Exception.ConnectRejected> { p.client.webTransport(wtReq(), listOf("chat")) }.status)
                withTimeout(5.seconds) { refused.await() }
            }
        }

    /** Section 3.3: a `WT-Protocol` the client did not offer closes the session with WT_ALPN_ERROR. */
    @Test fun negative_wtProtocolOutsideOfferIsAlpnError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L) + wtClientSettings)
                val client = Http3Connection.client(c, wtOn)
                launch {
                    val st = withTimeout(5.seconds) { s.acceptBidi() }
                    assertEquals("\"chat\"", readHeaders(st)["wt-available-protocols"])
                    st.output.writeFully(raw.headers(st.id, listOf(":status" to "200", "wt-protocol" to "\"other\"")))
                    st.output.flush()
                    assertEquals(Http3ErrorCode.WT_ALPN_ERROR, resetCode(st))
                }
                val e = assertFailsWith<WebTransportException.Alpn> { client.webTransport(wtReq(), listOf("chat")) }
                assertEquals("other", e.selected)
            }
        }

    /** The client sends no CONNECT before the server's SETTINGS: it must know which draft the server speaks. */
    @Test fun wtBeforeServerSettingsWaits() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c, wtOn)
                val waiting = CompletableDeferred<Unit>()
                client.session.wtTimer = {
                    waiting.complete(Unit)
                    awaitCancellation()
                }
                val raw = RawPeer(s)
                val session = async { client.webTransport(wtReq()) }
                withTimeout(5.seconds) { waiting.await() } // the client waits for SETTINGS ...
                assertTrue(withContext(client.session.dispatcher) { client.session.clientStreams.isEmpty() }) // ... with no CONNECT out
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L) + wtClientSettings)
                val st = withTimeout(5.seconds) { s.acceptBidi() }
                assertEquals(WtTokens.H3, readHeaders(st)[":protocol"])
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flush()
                withTimeout(5.seconds) { session.await() }
            }
        }

    @Test fun negative_wtWithoutServerSupportFails() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = connectOnly).useScoped { p ->
                assertFailsWith<Http3Exception.Settings> { p.client.webTransport(wtReq()) }
            }
        }

    @Test fun clientWithoutWebTransportSettingFails() =
        h3Test {
            H3Pair.open(clientSettings = connectOnly, serverSettings = wtOn).useScoped { p ->
                assertFailsWith<IllegalStateException> { p.client.webTransport(wtReq()) }
            }
        }

    /** Sections 3.1, 7.1: the server waits for the client's SETTINGS, and not forever; without them the request is malformed. */
    @Test fun negative_acceptWithoutClientSettingsFails() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val asked = CompletableDeferred<Duration>()
                server.session.wtTimer = { asked.complete(it) } // the deadline passes at once
                val raw = RawPeer(c)
                val st = c.openBidi()
                st.output.writeFully(raw.wtConnect(st))
                st.output.flush()
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                assertFailsWith<Http3Exception.Settings> { r.acceptWebTransport() }
                assertEquals(10.seconds, asked.await())
                assertEquals("400", readHeaders(st)[":status"])
            }
        }

    @Test fun negative_acceptWithoutClientDatagramsIs400() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(listOf(SettingsId.WT_ENABLED to 1L))
                val st = c.openBidi()
                st.output.writeFully(raw.wtConnect(st))
                st.output.flush()
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                assertFailsWith<Http3Exception.Settings> { r.acceptWebTransport() }
                assertEquals("400", readHeaders(st)[":status"])
            }
        }

    /** The answer to the CONNECT has a deadline too: an unanswered CONNECT is reset and the call fails. */
    @Test fun negative_unansweredConnectTimesOut() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L) + wtClientSettings)
                val client = Http3Connection.client(c, wtOn)
                withTimeout(5.seconds) { client.peerSettings.filterNotNull().first() }
                val expire = CompletableDeferred<Unit>()
                client.session.wtTimer = { expire.await() }
                val call = async { runCatching { client.webTransport(wtReq()) } }
                val st = withTimeout(5.seconds) { s.acceptBidi() }
                readHeaders(st) // the CONNECT is out; the server never answers
                expire.complete(Unit)
                assertIs<WebTransportException.Timeout>(withTimeout(5.seconds) { call.await() }.exceptionOrNull())
                assertEquals(Http3ErrorCode.REQUEST_CANCELLED, resetCode(st))
                // the slot is free again
                assertFalse(withContext(client.session.dispatcher) { client.session.wtClientBusy })
            }
        }

    /** Section 3.3: a `WT-Protocol` that is no Structured Field String is ignored, as if absent. */
    @Test fun malformedWtProtocolIsIgnored() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L) + wtClientSettings)
                val client = Http3Connection.client(c, wtOn)
                launch {
                    val st = withTimeout(5.seconds) { s.acceptBidi() }
                    readHeaders(st)
                    st.output.writeFully(raw.headers(st.id, listOf(":status" to "200", "wt-protocol" to "chat")))
                    st.output.flush()
                }
                assertNull(client.webTransport(wtReq(), listOf("chat")).protocol)
            }
        }

    /** The WebTransport token without our setting is an ordinary Extended CONNECT, left to the application. */
    @Test fun tokenWithoutSettingIsPlainConnect() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, connectOnly)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val st = c.openBidi()
                st.output.writeFully(raw.wtConnect(st))
                st.output.flush()
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                assertFalse(r.isWebTransport)
                assertFailsWith<IllegalStateException> { r.acceptWebTransport() }
            }
        }

    /** A stream that came before its session's CONNECT was accepted waits, then reaches the session (section 4.6). */
    @Test fun bufferedStreamDeliveredOnAccept() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val connect = c.openBidi() // its id names the session; its HEADERS go out after the stream
                raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + "early".encodeToByteArray(), fin = true)
                withTimeout(5.seconds) {
                    server.session.wt.bufferedCount
                        .awaitValue(1)
                }
                connect.output.writeFully(raw.wtConnect(connect))
                connect.output.flush()
                val session = server.acceptRequest().acceptWebTransport()
                val st = withTimeout(5.seconds) { session.acceptUni() }
                assertEquals("early", st.input.readAllBytes().decodeToString())
            }
        }
}

private suspend fun kotlinx.coroutines.flow.StateFlow<Int>.awaitValue(n: Int) {
    first { it == n }

    /** RFC 9297 section 3.2: a CONNECT with content-type rules out capsules: 400, never 200 and then a reset. */
    @Test fun negative_capsuleIncompatibleRequestIs400() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val st = c.openBidi()
                st.output.writeFully(raw.wtConnect(st, WtTokens.H3, "content-type" to "text/plain"))
                st.output.flush()
                val r = withTimeout(5.seconds) { server.acceptRequest() }
                assertFailsWith<Http3Exception.MessageError> { r.acceptWebTransport() }
                assertEquals("400", readHeaders(st)[":status"])
            }
        }
}
