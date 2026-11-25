// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.acceptBidi
import io.kuicksilver.http3.runtime.awaitCondition
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerMayHaveClosed
import io.kuicksilver.http3.runtime.peerStopped
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A session that ends because the peer broke it ([WtSessionImpl]'s `End.Failed`: a malformed WT_CLOSE_SESSION; and
 * `End.FlowControl`: a capsule section 5.4 prohibits, from draft-14 on) resets its CONNECT stream both ways. Its exchange
 * must still end, so the connection's count of sessions goes back to 0 and the slot is free for the next session: on the
 * client (`wtClientSessions`) and on the server (`wtSessions`), in every draft each break applies to.
 */
class WtFailedEndTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Draft(
        val settings: List<Pair<Long, Long>>,
        val token: String,
        val fields: List<Pair<String, String>>,
        val version: WtVersion,
    ) {
        override fun toString() = version.toString()
    }

    private val drafts =
        listOf(
            Draft(listOf(SettingsId.WT_ENABLED_DRAFT17 to 1L), WtTokens.H3, emptyList(), WtVersion.Draft17),
            Draft(listOf(SettingsId.WT_ENABLED_DRAFT16 to 1L), WtTokens.H3, emptyList(), WtVersion.Draft16),
            Draft(listOf(SettingsId.WT_MAX_SESSIONS_DRAFT14 to 1L), WtTokens.LEGACY, emptyList(), WtVersion.Draft14),
            Draft(
                listOf(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L),
                WtTokens.LEGACY,
                listOf(WtTokens.DRAFT02_REQUEST_FIELD to "1"),
                WtVersion.Draft02,
            ),
        )

    /** A capsule that breaks the session: `End.Failed` (a reason that is not UTF-8) or `End.FlowControl`. */
    private fun breaking(flowControl: Boolean): ByteArray =
        if (flowControl) {
            capsuleBytes(WtFlow.MAX_STREAM_DATA, VarInt.encode(1))
        } else {
            capsuleBytes(WtCloseCapsule.TYPE, byteArrayOf(0, 0, 0, 7, 0xff.toByte()))
        }

    /** The breaks [d] can see: a malformed close in every draft, a prohibited capsule from draft-14 on (draft-02 has none). */
    private fun breaksOf(d: Draft) = if (d.version == WtVersion.Draft02) listOf(false) else listOf(false, true)

    @Test fun negative_aClientSessionBrokenByTheServerGivesItsSlotBack() =
        h3Test {
            for (d in drafts.filter { it.version in WtVersion.ours(isServer = false) }) {
                for (flowControl in breaksOf(d)) {
                    QuicPair.open(H3Fixtures.quic).useScoped { q ->
                        val (c, s) = q.connect(H3Fixtures.quic)
                        val raw = RawPeer(s)
                        raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L, SettingsId.H3_DATAGRAM to 1L) + d.settings)
                        val client = Http3Connection.client(c, wtOn)
                        val opening = async { client.webTransport(wtReq()) }
                        val st = withTimeout(5.seconds) { s.acceptBidi() }
                        readHeaders(st)
                        st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                        st.output.flush()
                        val session = withTimeout(5.seconds) { opening.await() }
                        peerMayHaveClosed {
                            st.output.writeFully(RawPeer.dataFrame(breaking(flowControl)))
                            st.output.flush()
                        }
                        assertNotNull(withTimeout(5.seconds) { session.closed.await() }.cause, "$d, flow control $flowControl")
                        awaitCondition("$d, flow control $flowControl: the client's session count back to 0") {
                            withContext(client.session.dispatcher) { client.session.wtClientSessions == 0 }
                        }
                    }
                }
            }
        }

    @Test fun negative_aServerSessionBrokenByTheClientGivesItsSlotBack() =
        h3Test {
            for (d in drafts) {
                for (flowControl in breaksOf(d)) {
                    QuicPair.open(H3Fixtures.quic).useScoped { q ->
                        val (c, s) = q.connect(H3Fixtures.quic)
                        val server = Http3Connection.server(s, wtOn)
                        val raw = RawPeer(c)
                        raw.openControl(listOf(SettingsId.H3_DATAGRAM to 1L) + d.settings)
                        val accepted = async { server.acceptRequest().acceptWebTransport() }
                        val st = c.openBidi()
                        st.output.writeFully(raw.wtConnect(st, d.token, *d.fields.toTypedArray()))
                        st.output.flush()
                        readHeaders(st)
                        val session = withTimeout(5.seconds) { accepted.await() }
                        peerMayHaveClosed {
                            st.output.writeFully(RawPeer.dataFrame(breaking(flowControl)))
                            st.output.flush()
                        }
                        assertNotNull(withTimeout(5.seconds) { session.closed.await() }.cause, "$d, flow control $flowControl")
                        awaitCondition("$d, flow control $flowControl: the server's session count back to 0") {
                            withContext(server.session.dispatcher) { server.session.wtSessions.isEmpty() }
                        }
                    }
                }
            }
        }

    /**
     * A peer that never answers: after our close (or the session's failure) its FIN does not come, nor the RESET_STREAM
     * that RFC 9000 section 3.5 requires in answer to our STOP_SENDING (here every datagram of it is lost from then on).
     * The session's exchange must still end within a bound, two of its close timeouts, so the count goes back to 0: on
     * the server for a local close and a failed session, on the client for a local close.
     */
    @Test fun negative_aPeerThatIgnoresOurStopSendingStillGivesTheSlotBack() =
        h3Test {
            for (failed in listOf(false, true)) {
                QuicPair.open(H3Fixtures.quic).useScoped { q ->
                    val (c, s) = q.connect(H3Fixtures.quic)
                    val server = Http3Connection.server(s, wtOn)
                    val raw = RawPeer(c)
                    raw.openControl(listOf(SettingsId.H3_DATAGRAM to 1L, SettingsId.WT_ENABLED_DRAFT17 to 1L))
                    val accepted = async { server.acceptRequest().acceptWebTransport() }
                    val st = c.openBidi()
                    st.output.writeFully(raw.wtConnect(st, WtTokens.H3))
                    st.output.flush()
                    readHeaders(st)
                    val session = withTimeout(5.seconds) { accepted.await() } as WtSessionImpl
                    session.closeTimeout = 200.milliseconds
                    val clientAddr = c.paths.first().localAddress
                    if (failed) {
                        // the breaking capsule goes out first, then the client falls silent (the server may stop the stream
                        // with H3_MESSAGE_ERROR, a malformed session, before our flush returns; nothing else is tolerated)
                        peerStopped(Http3ErrorCode.MESSAGE_ERROR) {
                            st.output.writeFully(RawPeer.dataFrame(breaking(flowControl = false)))
                            st.output.flush()
                        }
                        withTimeout(5.seconds) { session.closed.await() }
                        q.net.drop = { from, _, _ -> from == clientAddr }
                    } else {
                        q.net.drop = { from, _, _ -> from == clientAddr }
                        session.close(7, "bye")
                    }
                    awaitCondition("failed $failed: the server's session count back to 0") {
                        withContext(server.session.dispatcher) { server.session.wtSessions.isEmpty() }
                    }
                    kotlin.test.assertFalse(server.closed.isCompleted, "failed $failed: the connection is still up")
                    q.net.drop = null
                }
            }
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val raw = RawPeer(s)
                raw.openControl(
                    listOf(
                        SettingsId.ENABLE_CONNECT_PROTOCOL to 1L,
                        SettingsId.H3_DATAGRAM to 1L,
                        SettingsId.WT_ENABLED_DRAFT17 to 1L,
                    ),
                )
                val client = Http3Connection.client(c, wtOn)
                val opening = async { client.webTransport(wtReq()) }
                val st = withTimeout(5.seconds) { s.acceptBidi() }
                readHeaders(st)
                st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                st.output.flush()
                val session = withTimeout(5.seconds) { opening.await() } as WtSessionImpl
                session.closeTimeout = 200.milliseconds
                val serverAddr = s.paths.first().localAddress
                q.net.drop = { from, _, _ -> from == serverAddr }
                session.close(7, "bye")
                awaitCondition("the client's session count back to 0") {
                    withContext(client.session.dispatcher) { client.session.wtClientSessions == 0 }
                }
                kotlin.test.assertFalse(client.closed.isCompleted, "the connection is still up")
                q.net.drop = null
            }
        }
}
