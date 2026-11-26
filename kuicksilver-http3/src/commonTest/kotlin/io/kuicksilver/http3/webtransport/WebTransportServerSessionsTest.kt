// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerMayHaveClosed
import io.kuicksilver.http3.runtime.readVarInt
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A server with several WebTransport sessions on one connection (draft-ietf-webtrans-http3-16 sections 4, 5.1, 5.2, 4.7,
 * 6; draft-14 section 5.2): streams go to their own session, one session's end leaves the others and the connection, and
 * a session beyond the limit, or without flow control, is refused with H3_REQUEST_REJECTED before the application.
 */
class WebTransportServerSessionsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private companion object {
        const val BUFFER = 262_144L
    }

    private class Raw(
        val c: QuicConnection,
        val server: Http3Connection,
        val raw: RawPeer,
    )

    private fun serverTest(
        serverSettings: Http3Settings = wtOn,
        clientSettings: List<Pair<Long, Long>> = wtClientFlowSettings(),
        serverQuic: QuicConfig = H3Fixtures.quic,
        clientQuic: QuicConfig = H3Fixtures.quic,
        block: suspend CoroutineScope.(Raw) -> Unit,
    ) = h3Test {
        QuicPair.open(serverQuic).useScoped { q ->
            val (c, s) = q.connect(clientQuic)
            val server = Http3Connection.server(s, serverSettings)
            val raw = RawPeer(c)
            raw.openControl(clientSettings)
            block(Raw(c, server, raw))
        }
    }

    private suspend fun Raw.uniTo(
        session: QuicStream,
        text: String,
    ) = raw.uni(StreamType.WT_UNI, VarInt.encode(session.id) + text.encodeToByteArray(), fin = true)

    private suspend fun WebTransportSession.nextUniText(): String =
        withTimeout(5.seconds) { acceptUni().input.readAllBytes().decodeToString() }

    /** A CONNECT the server refuses before the application: reset with H3_REQUEST_REJECTED. */
    private suspend fun Raw.refusedConnect(
        token: String = WtTokens.H3,
        vararg extra: Pair<String, String>,
    ) {
        val st = c.openBidi()
        peerMayHaveClosed {
            st.output.writeFully(raw.wtConnect(st, token, *extra))
            st.output.flush()
        }
        assertEquals(Http3ErrorCode.REQUEST_REJECTED, resetCode(st))
    }

    @Test fun twoSessionsShareTheConnectionAndKeepTheirStreams() =
        serverTest { r ->
            val (a, sa) = rawSession(r.c, r.server, r.raw)
            val (b, sb) = rawSession(r.c, r.server, r.raw)
            assertNotEquals(sa.sessionId, sb.sessionId)
            r.uniTo(b, "to b")
            r.uniTo(a, "to a")
            assertEquals("to a", sa.nextUniText())
            assertEquals("to b", sb.nextUniText())
            // the server's own streams carry their session's ID too
            val out = sb.openUni()
            out.output.writeFully("from b".encodeToByteArray())
            out.output.flushAndClose()
            // the server's control and QPACK streams come first: the WebTransport one is the stream of type 0x54
            val body =
                withTimeout(5.seconds) {
                    while (true) {
                        val st = r.c.acceptStream()
                        if (st.readVarInt() == StreamType.WT_UNI) return@withTimeout st.input.readAllBytes()
                    }
                    @Suppress("UNREACHABLE_CODE")
                    error("unreachable")
                }
            assertEquals(VarInt.encode(sb.sessionId).toList() + "from b".encodeToByteArray().toList(), body.toList())
            assertTrue(sa.flow != null && sb.flow != null)
            // section 8: the connection's receive window holds what both sessions may have in flight
            @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
            withTimeout(5.seconds) {
                while (io.kuicksilver.quic.runtime.QuicStreamLimits
                        .receiveLimit(r.server.quic)!! < 2 * wtOn.webTransportInitialMaxData
                ) {
                    kotlinx.coroutines.yield()
                }
            }
        }

    /** Section 6: one session's end (either side, cleanly or by a reset) leaves the others and the connection alone. */
    @Test fun oneSessionEndingLeavesTheOthers() =
        serverTest { r ->
            val (a, sa) = rawSession(r.c, r.server, r.raw)
            val (b, sb) = rawSession(r.c, r.server, r.raw)
            val (c3, sc) = rawSession(r.c, r.server, r.raw)
            launch { sa.close(7, "bye") } // returns once the client answered with its FIN, which this client never sends
            assertEquals(7L, withTimeout(5.seconds) { sa.closed.await() }.code)
            // the client resets the third session's CONNECT stream
            c3.reset(Http3ErrorCode.REQUEST_CANCELLED)
            withTimeout(5.seconds) { sc.closed.await() }
            r.uniTo(b, "still")
            assertEquals("still", sb.nextUniText())
            assertFalse(sb.closed.isCompleted)
            assertFalse(r.server.closed.isCompleted)
            assertNotNull(a)
        }

    /** Section 5.2 (draft-14 section 5.2): beyond webTransportMaxSessions a CONNECT is refused; a freed slot takes one again. */
    @Test fun negative_sessionBeyondTheLimitIsRefused() =
        serverTest(serverSettings = wtOn.toBuilder().apply { webTransportMaxSessions = 2 }.build()) { r ->
            val (a, sa) = rawSession(r.c, r.server, r.raw)
            val (b, sb) = rawSession(r.c, r.server, r.raw)
            r.refusedConnect()
            assertFalse(r.server.closed.isCompleted, "the connection stays")
            r.uniTo(b, "b lives")
            assertEquals("b lives", sb.nextUniText())
            // close() returns once the peer answered with its FIN: the client reads the close and answers meanwhile, and the
            // CONNECT stream is then over both ways, its slot free
            val closing = launch { sa.close(0, "") }
            a.input.readAllBytes()
            a.output.flushAndClose()
            closing.join()
            withTimeout(5.seconds) {
                while (withContextOf(r.server) { a.id in r.server.session.wtSessions }) kotlinx.coroutines.yield()
            }
            val (_, s3) = rawSession(r.c, r.server, r.raw)
            r.uniTo(b, "b again")
            assertEquals("b again", sb.nextUniText())
            assertFalse(s3.closed.isCompleted)
        }

    /**
     * Section 8: a session whose peer never reads one of its streams holds only its share of the connection's send buffer
     * (QUIC's `maxSendBuffer`), so another session's data still goes through. Without the share the first session's
     * writer filled the buffer while holding the turn, and every session stalled.
     */
    @Test fun negative_aSessionWhosePeerNeverReadsDoesNotStallTheOthers() =
        smallBufferTest { r ->
            val (_, sa) = rawSession(r.c, r.server, r.raw)
            val (_, sb) = rawSession(r.c, r.server, r.raw)
            val share = assertNotNull((sa as WtSessionImpl).sendShareForTest)
            // two sessions split the buffer less the reserve (one part in webTransportMaxSessions + 1)
            assertEquals((BUFFER - BUFFER / 5) / 2, share.cap)
            val flooding = r.flood(sa, share)
            assertTrue(r.sendAndReceive(sb, 500_000), "the other session's data arrived whole")
            assertTrue(share.held.value <= share.cap, "the stuck session stays within its share")
            flooding.cancel()
        }

    /**
     * A session alone on its connection is not held to the part it would have among many: it may use the whole buffer
     * less the reserve, so one session's throughput is not cut to a fraction of the buffer per round trip.
     */
    @Test fun aLoneSessionUsesTheBufferLessTheReserve() =
        smallBufferTest { r ->
            val (_, sa) = rawSession(r.c, r.server, r.raw)
            val share = assertNotNull((sa as WtSessionImpl).sendShareForTest)
            assertEquals(BUFFER - BUFFER / 5, share.cap)
            val flooding = r.flood(sa, share)
            assertTrue(share.held.value > BUFFER / 5, "it holds more than one part in webTransportMaxSessions + 1")
            flooding.cancel()
        }

    /**
     * A session that joins while another holds its whole (alone) part finds the reserve free and writes at once; the first
     * one, over its smaller part now, waits until the transport released enough.
     */
    @Test fun negative_aSessionJoiningAFullBufferWritesAtOnce() =
        smallBufferTest { r ->
            val (_, sa) = rawSession(r.c, r.server, r.raw)
            val share = assertNotNull((sa as WtSessionImpl).sendShareForTest)
            val flooding = r.flood(sa, share)
            assertTrue(share.held.value > (BUFFER - BUFFER / 5) / 2, "the first session holds more than its later part")
            val (_, sb) = rawSession(r.c, r.server, r.raw)
            assertEquals((BUFFER - BUFFER / 5) / 2, share.cap)
            assertTrue(r.sendAndReceive(sb, 200_000), "the newcomer's data arrived whole")
            assertTrue(share.held.value <= BUFFER - BUFFER / 5)
            flooding.cancel()
        }

    /** A server send buffer of [BUFFER] bytes; the client takes at most 16 KiB of a stream it does not read. */
    private fun smallBufferTest(block: suspend CoroutineScope.(Raw) -> Unit) =
        serverTest(
            clientSettings = wtClientFlowSettings(data = 64_000_000),
            serverQuic =
                H3Fixtures.quic
                    .toBuilder()
                    .apply { flowControl { maxSendBuffer = BUFFER } }
                    .build(),
            clientQuic =
                H3Fixtures.quic
                    .toBuilder()
                    .apply {
                        flowControl { initialStreamWindow = 16_384 }
                        flowControl { maxStreamWindow = 16_384 }
                    }.build(),
            block = block,
        )

    /**
     * [session] writes to a stream the client never reads (16 KiB go out, the rest stays in the server's buffer) until its
     * share is full; the writer is returned for the caller to cancel.
     */
    private suspend fun Raw.flood(
        session: WebTransportSession,
        share: WtSendShare,
    ): kotlinx.coroutines.Job {
        val stuck = session.openUni()
        val job = server.session.scope.launch { runCatching { stuck.output.writeFully(ByteArray(4_000_000)) } }
        withTimeout(5.seconds) { share.held.first { it + WtFairness.SEND_QUANTUM > share.cap } }
        return job
    }

    /** [session] sends [size] bytes on a new stream the client reads; whether they all arrived within ten seconds. */
    private suspend fun Raw.sendAndReceive(
        session: WebTransportSession,
        size: Int,
    ): Boolean =
        kotlinx.coroutines.coroutineScope {
            val out = session.openUni()
            val data = ByteArray(size) { it.toByte() }
            launch {
                out.output.writeFully(data)
                out.output.flushAndClose()
            }
            val got =
                withTimeout(10.seconds) {
                    while (true) {
                        val st = c.acceptStream()
                        if (st.id and 2L == 0L || st.readVarInt() != StreamType.WT_UNI) continue
                        if (st.readVarInt() == session.sessionId) return@withTimeout st.input.readAllBytes()
                    }
                    @Suppress("UNREACHABLE_CODE")
                    error("unreachable")
                }
            data.contentEquals(got)
        }

    /**
     * Section 5.2: "Servers SHOULD limit the rate of incoming WebTransport sessions". Sessions opened and ended in a loop
     * meet the burst, then are refused unprocessed until the rate gives another.
     */
    @Test fun negative_sessionsOpenedAndEndedInALoopMeetTheRate() =
        serverTest { r ->
            var now = 0L
            r.server.session.glitchClock = { now }
            repeat(io.kuicksilver.http3.runtime.H3Session.WT_SESSION_BURST) {
                val (st, s) = rawSession(r.c, r.server, r.raw)
                st.reset(Http3ErrorCode.REQUEST_CANCELLED)
                st.stopSending(Http3ErrorCode.REQUEST_CANCELLED)
                withTimeout(5.seconds) { s.closed.await() }
                withTimeout(5.seconds) {
                    while (withContextOf(r.server) { st.id in r.server.session.wtSessions }) kotlinx.coroutines.yield()
                }
            }
            r.refusedConnect()
            assertFalse(r.server.closed.isCompleted, "the connection stays")
            now += 1_000_000_000L / io.kuicksilver.http3.runtime.H3Session.WT_SESSIONS_PER_SECOND // one more
            val (_, again) = rawSession(r.c, r.server, r.raw)
            assertFalse(again.closed.isCompleted)
            r.refusedConnect()
        }

    /**
     * The connection's loss ends the peer's streams nobody accepted, as any other end of the session does: they leave the
     * accept queues (with their counts stopped) instead of staying there.
     */
    @Test fun negative_connectionLossEndsTheStreamsNobodyAccepted() =
        serverTest { r ->
            val (a, sa) = rawSession(r.c, r.server, r.raw)
            repeat(3) { r.uniTo(a, "unread $it") }
            val impl = sa as WtSessionImpl
            withTimeout(5.seconds) { while (impl.waitingForTest < 3) kotlinx.coroutines.yield() }
            r.c.close()
            withTimeout(5.seconds) { sa.closed.await() }
            withTimeout(5.seconds) { while (impl.waitingForTest > 0) kotlinx.coroutines.yield() }
        }

    /** Two CONNECTs racing for the last slot: exactly one is admitted, the other refused. */
    @Test fun negative_connectsRacingForTheLastSlotAdmitOne() =
        serverTest(serverSettings = wtOn.toBuilder().apply { webTransportMaxSessions = 2 }.build()) { r ->
            rawSession(r.c, r.server, r.raw)
            launch { runCatching { r.server.acceptRequest().acceptWebTransport() } }
            val x = r.c.openBidi()
            val y = r.c.openBidi()
            peerMayHaveClosed {
                x.output.writeFully(r.raw.wtConnect(x))
                y.output.writeFully(r.raw.wtConnect(y))
                x.output.flush()
                y.output.flush()
            }
            val outcomes: Set<String> =
                listOf(x, y)
                    .map { st ->
                        runCatching { readHeaders(st)[":status"] ?: "none" }.getOrElse { "reset ${resetCode(st)}" }
                    }.toSet()
            assertEquals(setOf("200", "reset ${Http3ErrorCode.REQUEST_REJECTED}"), outcomes)
        }

    /** Section 5.1: a client that does not declare flow control keeps one session; a second is refused. */
    @Test fun negative_secondSessionWithoutTheClientsFlowControlIsRefused() =
        serverTest(clientSettings = wtClientSettings) { r ->
            val (a, sa) = rawSession(r.c, r.server, r.raw)
            r.refusedConnect()
            r.uniTo(a, "alive")
            assertEquals("alive", sa.nextUniText())
        }

    /** The same when the server declares none. */
    @Test fun negative_secondSessionWithoutTheServersFlowControlIsRefused() =
        serverTest(serverSettings = wtLimits(0, 0, 0)) { r ->
            rawSession(r.c, r.server, r.raw)
            r.refusedConnect()
        }

    /** draft-02 has no flow control: a draft-02 client's session keeps the connection to itself. */
    @Test fun negative_draft02SessionDoesNotShare() =
        serverTest(clientSettings = listOf(SettingsId.H3_DATAGRAM to 1L, SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L)) { r ->
            val accepted = rawLegacySession(r)
            assertTrue(accepted.flow == null)
            assertEquals(WtVersion.Draft02, (accepted as WtSessionImpl).version)
            r.refusedConnect(WtTokens.LEGACY, WtTokens.DRAFT02_REQUEST_FIELD to "1")
        }

    /**
     * draft-14: a client declares flow control with SETTINGS_WT_MAX_SESSIONS above 1 (its section 5.1), and its sessions
     * share the connection up to the server's SETTINGS_WT_MAX_SESSIONS.
     */
    @Test fun draft14ClientSessionsShareTheConnection() =
        serverTest(
            clientSettings = listOf(SettingsId.H3_DATAGRAM to 1L, SettingsId.WT_MAX_SESSIONS_DRAFT14 to 4L),
        ) { r ->
            val first = rawLegacySession(r, draft02 = false)
            val second = rawLegacySession(r, draft02 = false)
            assertNotNull(first.flow)
            assertNotNull(second.flow)
            assertEquals(WtVersion.Draft14, (second as WtSessionImpl).version)
        }

    /** Section 4.7: a GOAWAY asks every session to wind down; WT_DRAIN_SESSION only its own. */
    @Test fun goAwayDrainsEverySessionAndDrainOnlyItsOwn() =
        serverTest { r ->
            val (a, sa) = rawSession(r.c, r.server, r.raw)
            val (_, sb) = rawSession(r.c, r.server, r.raw)
            peerMayHaveClosed {
                a.output.writeFully(RawPeer.dataFrame(capsuleBytes(WT_DRAIN_SESSION, ByteArray(0))))
                a.output.flush()
            }
            withTimeout(5.seconds) { sa.drainRequested.first { it } }
            assertFalse(sb.drainRequested.value)
            r.raw.control.output
                .writeFully(r.raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(0)))
            r.raw.control.output
                .flush()
            withTimeout(5.seconds) { sb.drainRequested.first { it } }
            assertFalse(sb.closed.isCompleted)
        }

    /** The connection's loss ends every session with its reason. */
    @Test fun connectionLossEndsEverySession() =
        serverTest { r ->
            val (_, sa) = rawSession(r.c, r.server, r.raw)
            val (_, sb) = rawSession(r.c, r.server, r.raw)
            r.c.close(0x100, "gone")
            val ia = withTimeout(5.seconds) { sa.closed.await() }
            val ib = withTimeout(5.seconds) { sb.closed.await() }
            assertNotNull(ia.cause)
            assertNotNull(ib.cause)
        }

    /** A raw client's legacy-token session ([draft02]: with the draft-02 request field). */
    private suspend fun CoroutineScope.rawLegacySession(
        r: Raw,
        draft02: Boolean = true,
    ): WebTransportSession {
        val accepted = kotlinx.coroutines.CompletableDeferred<WebTransportSession>()
        launch {
            accepted.complete(r.server.acceptRequest().acceptWebTransport())
        }
        val st = r.c.openBidi()
        val extra = if (draft02) arrayOf(WtTokens.DRAFT02_REQUEST_FIELD to "1") else emptyArray()
        st.output.writeFully(r.raw.wtConnect(st, WtTokens.LEGACY, *extra))
        st.output.flush()
        assertEquals("200", readHeaders(st)[":status"])
        return withTimeout(5.seconds) { accepted.await() }
    }

    private suspend fun <T> withContextOf(
        h: Http3Connection,
        block: () -> T,
    ): T = kotlinx.coroutines.withContext(h.session.dispatcher) { block() }
}
