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

    private class Raw(
        val c: QuicConnection,
        val server: Http3Connection,
        val raw: RawPeer,
    )

    private fun serverTest(
        serverSettings: Http3Settings = wtOn,
        clientSettings: List<Pair<Long, Long>> = wtClientFlowSettings(),
        block: suspend CoroutineScope.(Raw) -> Unit,
    ) = h3Test {
        QuicPair.open(H3Fixtures.quic).useScoped { q ->
            val (c, s) = q.connect(H3Fixtures.quic)
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

    /** draft-02 has no flow control: a draft-02 session keeps the connection to itself, and joins no other. */
    @Test fun negative_draft02SessionDoesNotShare() =
        serverTest { r ->
            val accepted = rawLegacySession(r)
            assertTrue(accepted.flow == null)
            r.refusedConnect()
        }

    @Test fun negative_draft02SessionDoesNotJoin() =
        serverTest { r ->
            rawSession(r.c, r.server, r.raw)
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
