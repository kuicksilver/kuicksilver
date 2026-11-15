// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.WebTransportException
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.StoredSettings
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerMayHaveClosed
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** [wtOn] with WebTransport flow-control limits of our own. */
internal fun wtLimits(
    bidi: Long = 100,
    uni: Long = 100,
    data: Long = 15_728_640,
): Http3Settings =
    wtOn
        .toBuilder()
        .apply {
            webTransportInitialMaxStreamsBidi = bidi
            webTransportInitialMaxStreamsUni = uni
            webTransportInitialMaxData = data
        }.build()

/** The settings of a raw WebTransport client that declares flow control (draft-16 section 5.1) with these limits. */
internal fun wtClientFlowSettings(
    bidi: Long = 10,
    uni: Long = 10,
    data: Long = 100_000,
): List<Pair<Long, Long>> =
    wtClientSettings +
        listOf(
            SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to bidi,
            SettingsId.WT_INITIAL_MAX_STREAMS_UNI to uni,
            SettingsId.WT_INITIAL_MAX_DATA to data,
        )

/** A capsule on the wire (RFC 9297 section 3.2). */
internal fun capsuleBytes(
    type: Long,
    value: ByteArray,
): ByteArray = VarInt.encode(type) + VarInt.encode(value.size.toLong()) + value

/** The session's flow control, or null. */
internal val WebTransportSession.flow: WtSessionFlow? get() = (this as WtSessionImpl).flow

/** Waits until [cond], read on [h3]'s dispatcher, holds for [session]'s flow control. */
internal suspend fun Http3Connection.awaitFlow(
    session: WebTransportSession,
    cond: (WtSessionFlow) -> Boolean,
) {
    val f = assertNotNull(session.flow)
    withTimeout(5.seconds) {
        while (true) {
            val seen = f.changesForTest.value
            if (withContext(this@awaitFlow.session.dispatcher) { cond(f) }) return@withTimeout
            f.changesForTest.first { it != seen }
        }
    }
}

/** A raw client's session on [server]: its CONNECT stream once the 200 came, and the server's session. */
internal suspend fun CoroutineScope.rawSession(
    c: QuicConnection,
    server: Http3Connection,
    raw: RawPeer,
): Pair<QuicStream, WebTransportSession> {
    val accepted = CompletableDeferred<WebTransportSession>()
    launch { accepted.complete(server.acceptRequest().acceptWebTransport()) }
    val st = c.openBidi()
    st.output.writeFully(raw.wtConnect(st))
    st.output.flush()
    assertEquals("200", readHeaders(st)[":status"])
    return st to withTimeout(5.seconds) { accepted.await() }
}

/** The session closed for a flow-control violation and reset its CONNECT stream with WT_FLOW_CONTROL_ERROR. */
private suspend fun assertFlowControlClose(
    connect: QuicStream,
    session: WebTransportSession,
) {
    assertEquals(Http3ErrorCode.WT_FLOW_CONTROL_ERROR, resetCode(connect))
    assertIs<WebTransportException.FlowControl>(withTimeout(5.seconds) { session.closed.await() }.cause)
}

class WebTransportFlowControlTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Section 5.1: "If both endpoints take at least one of these actions, flow control is enabled". */
    @Test fun flowControlOnWhenBothSidesDeclareIt() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val session = p.client.webTransport(wtReq())
                assertNotNull(session.flow)
                assertNotNull(withTimeout(5.seconds) { serverSide.await() }.flow)
            }
        }

    @Test fun negative_noFlowControlWhenOneSideDoesNotDeclareIt() =
        h3Test {
            H3Pair.open(clientSettings = wtLimits(0, 0, 0), serverSettings = wtOn).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val session = p.client.webTransport(wtReq())
                assertNull(session.flow)
                assertNull(withTimeout(5.seconds) { serverSide.await() }.flow)
            }
        }

    /** Our flow-control settings go out only when non-zero, and declare the intent (section 5.5). */
    @Test fun settingsCarryTheInitialLimits() {
        val ours = WtSettings.ours(isServer = true, settings = wtLimits(7, 0, 9)).toMap()
        assertEquals(7L, ours[SettingsId.WT_INITIAL_MAX_STREAMS_BIDI])
        assertNull(ours[SettingsId.WT_INITIAL_MAX_STREAMS_UNI])
        assertEquals(9L, ours[SettingsId.WT_INITIAL_MAX_DATA])
        assertEquals(16L, ours[SettingsId.WT_MAX_SESSIONS_DRAFT14])
        // without flow control a draft-14 client is told one session, and nothing declares the intent
        val none = WtSettings.ours(isServer = true, settings = wtLimits(0, 0, 0)).toMap()
        assertEquals(1L, none[SettingsId.WT_MAX_SESSIONS_DRAFT14])
        assertFalse(WtFlow.declares(none, WtVersion.Draft16))
        assertFalse(WtFlow.declares(none, WtVersion.Draft14))
        // draft-14 section 5.1: "Sending SETTINGS_WT_MAX_SESSIONS with a value greater than "1"" declares it too
        assertTrue(WtFlow.declares(mapOf(SettingsId.WT_MAX_SESSIONS_DRAFT14 to 2L), WtVersion.Draft14))
        assertFalse(WtFlow.declares(mapOf(SettingsId.WT_MAX_SESSIONS_DRAFT14 to 2L), WtVersion.Draft16))
        // draft-02 has no flow control
        assertFalse(WtFlow.declares(ours, WtVersion.Draft02))
    }

    /**
     * Section 5.6.2: "An endpoint MUST NOT open more streams than permitted"; a blocked sender sends WT_STREAMS_BLOCKED
     * (5.6.3), and the receiver gives the slot back with WT_MAX_STREAMS as the stream closes (5.6).
     */
    @Test fun streamLimitHoldsAnOpenUntilWtMaxStreams() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtLimits(uni = 1)).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val session = p.client.webTransport(wtReq())
                val first = session.openUni()
                val second = async { session.openUni() }
                p.client.awaitFlow(session) { (it.sentForTest[WtFlow.STREAMS_BLOCKED_UNI] ?: 0) == 1 }
                assertFalse(second.isCompleted)
                first.output.writeFully("one".encodeToByteArray())
                first.output.flushAndClose()
                val s = withTimeout(5.seconds) { serverSide.await() }
                assertEquals(
                    "one",
                    s
                        .acceptUni()
                        .input
                        .readAllBytes()
                        .decodeToString(),
                )
                // the server's stream ended: WT_MAX_STREAMS 2, and the second open goes ahead
                withTimeout(5.seconds) { second.await() }
                assertEquals(2L, assertNotNull(session.flow).peerMaxStreamsForTest(bidi = false))
            }
        }

    /** Sections 5.4, 5.6.4, 5.6.5: writes wait for WT_MAX_DATA, a blocked sender says so, and every byte arrives. */
    @Test fun dataLimitHoldsWritesUntilWtMaxData() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtLimits(data = 1000)).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val session = p.client.webTransport(wtReq())
                val data = ByteArray(50_000) { it.toByte() }
                val st = session.openUni()
                launch {
                    st.output.writeFully(data)
                    st.output.flushAndClose()
                }
                val got = withTimeout(5.seconds) { serverSide.await() }.acceptUni().input.readAllBytes()
                assertContentEquals(data, got)
                val f = assertNotNull(session.flow)
                p.client.awaitFlow(session) { it.sendDataForTest.first > 1000 }
                assertTrue(withContext(p.client.session.dispatcher) { (f.sentForTest[WtFlow.DATA_BLOCKED] ?: 0) >= 1 })
            }
        }

    /**
     * Section 5.4: "For streams that were reset, implementing WT_MAX_DATA requires that the QUIC stack provide the
     * WebTransport implementation with information about the final size of streams": a reset stream the server never
     * accepted still counts its final size, so both sides agree on the credit it used.
     */
    @Test fun resetStreamCountsItsFinalSizeOnBothSides() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val session = p.client.webTransport(wtReq())
                val s = withTimeout(5.seconds) { serverSide.await() }
                val st = session.openBidi()
                st.output.writeFully(ByteArray(4000))
                st.output.flush()
                // taken from the credit before the reset: what never went out is given back by the final size
                p.client.awaitFlow(session) { it.sendDataForTest.second == 4000L }
                st.reset(3) // the server never accepts it
                val second = session.openUni()
                second.output.writeFully(ByteArray(100))
                second.output.flushAndClose()
                assertEquals(
                    100,
                    s
                        .acceptUni()
                        .input
                        .readAllBytes()
                        .size,
                )
                awaitAgreement(p.client, session, p.server, s)
            }
        }

    /** A stream the server never accepts counts by the final size its FIN gives (section 5.4). */
    @Test fun unreadStreamCountsItsFinalSize() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val session = p.client.webTransport(wtReq())
                val s = withTimeout(5.seconds) { serverSide.await() }
                val st = session.openBidi()
                st.output.writeFully(ByteArray(4000))
                st.output.flushAndClose()
                p.server.awaitFlow(s) { it.receiveDataForTest.second == 4000L }
                awaitAgreement(p.client, session, p.server, s)
            }
        }

    /** The same when the receiver stops reading: the reset that answers its STOP_SENDING carries the final size. */
    @Test fun stoppedStreamCountsItsFinalSizeOnBothSides() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val serverSide = CompletableDeferred<WebTransportSession>()
                launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
                val session = p.client.webTransport(wtReq())
                val s = withTimeout(5.seconds) { serverSide.await() }
                val st = session.openUni()
                launch {
                    runCatching {
                        st.output.writeFully(ByteArray(200_000))
                        st.output.flushAndClose()
                    }
                }
                s.acceptUni().stopSending(4)
                val second = session.openUni()
                second.output.writeFully(ByteArray(100))
                second.output.flushAndClose()
                assertEquals(
                    100,
                    s
                        .acceptUni()
                        .input
                        .readAllBytes()
                        .size,
                )
                awaitAgreement(p.client, session, p.server, s)
            }
        }

    /** A raw client that declares flow control, its session on a server with [serverSettings], then [block]. */
    private fun rawFlowTest(
        serverSettings: Http3Settings = wtOn,
        clientSettings: List<Pair<Long, Long>> = wtClientFlowSettings(),
        block: suspend CoroutineScope.(c: QuicConnection, raw: RawPeer, connect: QuicStream, session: WebTransportSession) -> Unit,
    ) = h3Test {
        QuicPair.open(H3Fixtures.quic).useScoped { q ->
            val (c, s) = q.connect(H3Fixtures.quic)
            val server = Http3Connection.server(s, serverSettings)
            val raw = RawPeer(c)
            raw.openControl(clientSettings)
            val (connect, session) = rawSession(c, server, raw)
            block(c, raw, connect, session)
            assertFalse(server.closed.isCompleted) // a session error, not a connection error
        }
    }

    /** A capsule on the CONNECT stream, in a DATA frame as HTTP/3 carries the Capsule Protocol (RFC 9297 section 3.1). */
    private suspend fun QuicStream.capsule(
        type: Long,
        value: ByteArray,
    ) = peerMayHaveClosed {
        output.writeFully(RawPeer.dataFrame(capsuleBytes(type, value)))
        output.flush()
    }

    /** Section 5.6.2: "If an endpoint receives an incoming stream for a session that would exceed the advertised Maximum Streams value". */
    @Test fun negative_streamBeyondTheLimitClosesTheSession() =
        rawFlowTest(serverSettings = wtLimits(uni = 1)) { _, raw, connect, session ->
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id), fin = true)
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id), fin = true)
            assertFlowControlClose(connect, session)
        }

    @Test fun negative_bidiStreamBeyondTheLimitClosesTheSession() =
        rawFlowTest(serverSettings = wtLimits(bidi = 1)) { c, _, connect, session ->
            c.wtBidi(connect.id)
            c.wtBidi(connect.id)
            assertFlowControlClose(connect, session)
        }

    /** Section 5.6.4: "If an endpoint receives Stream Body data in excess of this limit". */
    @Test fun negative_dataBeyondTheLimitClosesTheSession() =
        rawFlowTest(serverSettings = wtLimits(data = 100)) { _, raw, connect, session ->
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + ByteArray(1000), fin = true)
            assertFlowControlClose(connect, session)
        }

    /** One byte beyond the limit is too many (the limit itself passes, below). */
    @Test fun negative_dataOneByteBeyondTheLimitClosesTheSession() =
        rawFlowTest(serverSettings = wtLimits(data = 100)) { _, raw, connect, session ->
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + ByteArray(101), fin = true)
            assertFlowControlClose(connect, session)
        }

    /** The data limit holds across streams: two streams of 60 bytes pass a limit of 100 only together with credit. */
    @Test fun negative_dataSpreadOverStreamsBeyondTheLimitClosesTheSession() =
        rawFlowTest(serverSettings = wtLimits(data = 100)) { _, raw, connect, session ->
            // neither stream is read, so no credit comes back between them
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + ByteArray(60), fin = true)
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + ByteArray(60), fin = true)
            assertFlowControlClose(connect, session)
        }

    /** A reset stream counts its final size against the limit, unread bytes included (section 5.4). */
    @Test fun negative_resetStreamBeyondTheLimitClosesTheSession() =
        rawFlowTest(serverSettings = wtLimits(data = 100)) { _, raw, connect, session ->
            val header = VarInt.encode(StreamType.WT_UNI) + VarInt.encode(connect.id)
            val st = raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + ByteArray(150))
            // section 4.4: the header goes reliably, so the stream reaches its session whatever the reset discards
            @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
            st.resetAt(Http3ErrorCode.NO_ERROR, header.size.toLong())
            assertFlowControlClose(connect, session)
        }

    /** WT_MAX_STREAMS of exactly 2^60 is allowed (section 5.6.2: "This value cannot exceed 2^60"). */
    @Test fun wtMaxStreamsOf2To60IsAllowed() =
        rawFlowTest { _, raw, connect, session ->
            connect.capsule(WtFlow.MAX_STREAMS_BIDI, VarInt.encode(1L shl 60))
            connect.capsule(WtFlow.STREAMS_BLOCKED_UNI, VarInt.encode(1L shl 60))
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + "ok".encodeToByteArray(), fin = true)
            assertEquals(
                "ok",
                session
                    .acceptUni()
                    .input
                    .readAllBytes()
                    .decodeToString(),
            )
            assertEquals(
                1L shl 60,
                withContext((session as WtSessionImpl).dispatcherForTest) {
                    assertNotNull(session.flow).peerMaxStreamsForTest(true)
                },
            )
        }

    /** A WT_MAX_DATA that lowers the limit is as wrong as one that keeps it. */
    @Test fun negative_wtMaxDataThatLowersClosesTheSession() =
        rawFlowTest { _, _, connect, session ->
            connect.capsule(WtFlow.MAX_DATA, VarInt.encode(200_000))
            connect.capsule(WtFlow.MAX_DATA, VarInt.encode(150_000))
            assertFlowControlClose(connect, session)
        }

    /** The limit counts the body only: a header of any length (here a non-minimal Session ID) is free (section 5.4). */
    @Test fun dataUpToTheLimitPassesWhateverTheHeader() =
        rawFlowTest(serverSettings = wtLimits(data = 100)) { _, raw, connect, session ->
            val longId = byteArrayOf(0xc0.toByte(), 0, 0, 0, 0, 0, 0, connect.id.toByte())
            raw.uni(StreamType.WT_UNI, longId + ByteArray(100), fin = true)
            assertEquals(
                100,
                session
                    .acceptUni()
                    .input
                    .readAllBytes()
                    .size,
            )
            assertFalse(session.closed.isCompleted)
        }

    /** Section 5.6.4: "a WT_MAX_DATA capsule with a Maximum Data value that does not increase the Maximum Data value previously received". */
    @Test fun negative_wtMaxDataThatDoesNotIncreaseClosesTheSession() =
        rawFlowTest { _, _, connect, session ->
            connect.capsule(WtFlow.MAX_DATA, VarInt.encode(100_000)) // the client's SETTINGS_WT_INITIAL_MAX_DATA
            assertFlowControlClose(connect, session)
        }

    /** Section 5.6.2: "If an endpoint receives a WT_MAX_STREAMS capsule that does not increase the Maximum Streams value". */
    @Test fun negative_wtMaxStreamsThatDoesNotIncreaseClosesTheSession() =
        rawFlowTest { _, _, connect, session ->
            connect.capsule(WtFlow.MAX_STREAMS_UNI, VarInt.encode(5))
            assertFlowControlClose(connect, session)
        }

    /** Section 5.6.2: "Recipients of a capsule with a Maximum Streams value larger than this limit". */
    @Test fun negative_wtMaxStreamsBeyond2To60ClosesTheSession() =
        rawFlowTest { _, _, connect, session ->
            connect.capsule(WtFlow.MAX_STREAMS_BIDI, VarInt.encode((1L shl 60) + 1))
            assertFlowControlClose(connect, session)
        }

    /** Section 5.6.3: the same bound for WT_STREAMS_BLOCKED. */
    @Test fun negative_wtStreamsBlockedBeyond2To60ClosesTheSession() =
        rawFlowTest { _, _, connect, session ->
            connect.capsule(WtFlow.STREAMS_BLOCKED_UNI, VarInt.encode((1L shl 60) + 1))
            assertFlowControlClose(connect, session)
        }

    /** A raised limit is taken: the server opens streams up to the client's new WT_MAX_STREAMS. */
    @Test fun wtMaxStreamsRaisesTheLimit() =
        rawFlowTest(clientSettings = wtClientFlowSettings(uni = 1)) { _, _, connect, session ->
            session.openUni().output.flushAndClose()
            connect.capsule(WtFlow.MAX_STREAMS_UNI, VarInt.encode(2))
            session.openUni().output.flushAndClose()
            assertFalse(session.closed.isCompleted)
            assertEquals(
                2L,
                withContext((session as WtSessionImpl).dispatcherForTest) { assertNotNull(session.flow).peerMaxStreamsForTest(false) },
            )
        }

    /** Section 5.4: "Endpoints MUST treat receipt of a WT_MAX_STREAM_DATA or a WT_STREAM_DATA_BLOCKED capsule as a session error". */
    @Test fun negative_wtMaxStreamDataIsASessionError() =
        rawFlowTest { _, _, connect, session ->
            connect.capsule(WtFlow.MAX_STREAM_DATA, VarInt.encode(4) + VarInt.encode(1000))
            assertFlowControlClose(connect, session)
        }

    @Test fun negative_wtStreamDataBlockedIsASessionError() =
        rawFlowTest(clientSettings = wtClientSettings) { _, _, connect, session ->
            // also without flow control: these are no flow-control capsules of section 5.6, and never used over HTTP/3
            connect.capsule(WtFlow.STREAM_DATA_BLOCKED, VarInt.encode(4) + VarInt.encode(1000))
            assertFlowControlClose(connect, session)
        }

    /** A flow-control capsule whose value is not one variable-length integer is malformed (H3_MESSAGE_ERROR). */
    @Test fun negative_malformedFlowControlCapsule() =
        rawFlowTest { _, _, connect, session ->
            connect.capsule(WtFlow.MAX_DATA, VarInt.encode(200_000) + byteArrayOf(1))
            assertEquals(Http3ErrorCode.MESSAGE_ERROR, resetCode(connect))
            withTimeout(5.seconds) { session.closed.await() }
        }

    /**
     * Section 5.1: "if flow control is not enabled, an endpoint MUST ignore receipt of any flow control capsules": one that
     * would close a session with flow control changes nothing here.
     */
    @Test fun flowControlCapsulesIgnoredWithoutFlowControl() =
        rawFlowTest(clientSettings = wtClientSettings) { _, raw, connect, session ->
            assertNull(session.flow)
            connect.capsule(WtFlow.MAX_DATA, VarInt.encode(0))
            connect.capsule(WtFlow.MAX_STREAMS_UNI, VarInt.encode((1L shl 60) + 1))
            raw.uni(StreamType.WT_UNI, VarInt.encode(connect.id) + "on".encodeToByteArray(), fin = true)
            assertEquals(
                "on",
                session
                    .acceptUni()
                    .input
                    .readAllBytes()
                    .decodeToString(),
            )
            assertFalse(session.closed.isCompleted)
        }

    /**
     * Section 3.2: "A client MUST close the connection with H3_SETTINGS_ERROR if the SETTINGS frame received in the
     * resumed connection reduces any flow control values from the cached previous values": the stored settings check
     * covers them.
     */
    @Test fun negative_resumedSettingsThatLowerFlowControlAreIncompatible() {
        val stored =
            mapOf(
                SettingsId.WT_ENABLED to 1L,
                SettingsId.WT_INITIAL_MAX_DATA to 1000L,
                SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to 10L,
            )
        assertNull(StoredSettings.incompatibility(stored, stored))
        assertNotNull(StoredSettings.incompatibility(stored, stored + (SettingsId.WT_INITIAL_MAX_DATA to 999L)))
        assertNotNull(StoredSettings.incompatibility(stored, stored + (SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to 9L)))
        assertNotNull(StoredSettings.incompatibility(stored, stored - SettingsId.WT_INITIAL_MAX_STREAMS_BIDI))
        assertNull(StoredSettings.incompatibility(stored, stored + (SettingsId.WT_INITIAL_MAX_STREAMS_UNI to 5L)))
    }

    /**
     * Section 3.2: "If the server accepts 0-RTT, the server MUST NOT reduce these initial flow control values": they are
     * bound into the server's tickets, so a server whose values changed accepts no early data.
     */
    @Test fun negative_serverTicketsBindTheFlowControlValues() {
        val ctx = wtOn.earlyDataContext()
        assertFalse(ctx.contentEquals(wtLimits(data = 1).earlyDataContext()))
        assertFalse(ctx.contentEquals(wtLimits(bidi = 1).earlyDataContext()))
        assertFalse(ctx.contentEquals(wtLimits(uni = 1).earlyDataContext()))
        assertFalse(
            ctx.contentEquals(
                wtOn
                    .toBuilder()
                    .apply { webTransportMaxSessions = 2 }
                    .build()
                    .earlyDataContext(),
            ),
        )
        assertContentEquals(ctx, wtLimits().earlyDataContext())
    }
}

/** Waits until the body bytes [client] counted as sent on [cs] equal what [server] counted as received on [ss]. */
internal suspend fun awaitAgreement(
    client: Http3Connection,
    cs: WebTransportSession,
    server: Http3Connection,
    ss: WebTransportSession,
) {
    val f1 = assertNotNull(cs.flow)
    val f2 = assertNotNull(ss.flow)
    withTimeout(5.seconds) {
        while (true) {
            val seen = f1.changesForTest.value to f2.changesForTest.value
            val sent = withContext(client.session.dispatcher) { f1.sendDataForTest.second }
            val received = withContext(server.session.dispatcher) { f2.receiveDataForTest.second }
            if (sent == received) return@withTimeout
            combine(f1.changesForTest, f2.changesForTest) { a, b -> a to b }.first { it != seen }
        }
    }
}
