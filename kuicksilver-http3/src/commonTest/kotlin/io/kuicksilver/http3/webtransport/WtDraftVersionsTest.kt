// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.GET
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.acceptBidi
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerMayHaveClosed
import io.kuicksilver.http3.runtime.peerSawClose
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * One peer per WebTransport draft we speak, as the field has them: draft-17 (this library and the draft of November
 * 2026), draft-16 (webtransport-go and picoquic, `SETTINGS_WT_ENABLED` 0x2c7cf000), draft-14 (Safari 26.4, second-hand:
 * `SETTINGS_WT_MAX_SESSIONS`) and draft-02 (Chrome and Firefox: `SETTINGS_ENABLE_WEBTRANSPORT`). Each meets our server
 * as a raw client, and the server ones meet our client as a raw server: the version both select (draft-17 section 7.1),
 * the token and the fields on the wire.
 */
class WtDraftVersionsTest {
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

    /** A raw client of [settings] sends a WebTransport CONNECT of [token] and [fields]; returns the response and the session. */
    private suspend fun kotlinx.coroutines.CoroutineScope.serve(
        settings: List<Pair<Long, Long>>,
        token: String,
        fields: List<Pair<String, String>> = emptyList(),
    ): Pair<Map<String, String>, Result<WtSessionImpl>> {
        var out: Pair<Map<String, String>, Result<WtSessionImpl>>? = null
        QuicPair.open(H3Fixtures.quic).useScoped { q ->
            val (c, s) = q.connect(H3Fixtures.quic)
            val server = Http3Connection.server(s, wtOn)
            val raw = RawPeer(c)
            raw.openControl(listOf(SettingsId.H3_DATAGRAM to 1L) + settings)
            val accepted = async { runCatching { server.acceptRequest().acceptWebTransport() as WtSessionImpl } }
            val st = c.openBidi()
            st.output.writeFully(raw.wtConnect(st, token, *fields.toTypedArray()))
            st.output.flush()
            val h = readHeaders(st)
            out = h to withTimeout(5.seconds) { accepted.await() }
        }
        return out!!
    }

    /** Every draft's client is served in its own draft; only a draft-02 one is answered with the draft-02 field (shim 2). */
    @Test fun eachDraftClientIsServedInItsDraft() =
        h3Test {
            for (d in drafts) {
                val (h, session) = serve(d.settings, d.token, d.fields)
                assertEquals("200", h[":status"], "$d")
                assertEquals(d.version, session.getOrThrow().version, "$d")
                assertEquals(
                    if (d.version ==
                        WtVersion.Draft02
                    ) {
                        WtTokens.DRAFT02_RESPONSE_VALUE
                    } else {
                        null
                    },
                    h[WtTokens.DRAFT02_RESPONSE_FIELD],
                    "$d",
                )
            }
        }

    /**
     * draft-17 section 7.1: "If the client sends the codepoint in Section 9.2, the server selects the version described in
     * this document", whatever else it sends; otherwise "the highest of those versions".
     */
    @Test fun serverSelectsTheHighestDraftTheClientSends() =
        h3Test {
            val all = drafts.flatMap { it.settings }
            assertEquals(WtVersion.Draft17, serve(all, WtTokens.H3).second.getOrThrow().version)
            assertEquals(WtVersion.Draft16, serve(all - drafts[0].settings.toSet(), WtTokens.H3).second.getOrThrow().version)
        }

    /**
     * draft-17 section 7.1: "Otherwise, the server selects the version described in this document. For example, a client
     * that supports only the version described in this document does not send SETTINGS_WT_ENABLED, so the server selects
     * that version." Before draft-17 such a client was refused.
     */
    @Test fun clientWithoutWtSettingGetsDraft17() =
        h3Test {
            val (h, session) = serve(emptyList(), WtTokens.H3)
            assertEquals("200", h[":status"])
            assertEquals(WtVersion.Draft17, session.getOrThrow().version)
        }

    /**
     * The same client with the token of draft-02 to -14: section 7.1 selected draft-17, whose token is `webtransport-h3`
     * (section 3.1), and the older drafts need their own setting (draft-02 and draft-14 section 3.1), so the request is
     * no WebTransport request of any version it could run: malformed, 400.
     */
    @Test fun negative_clientWithoutWtSettingAndTheOlderTokenIsMalformed() =
        h3Test {
            val (h, session) = serve(emptyList(), WtTokens.LEGACY, listOf(WtTokens.DRAFT02_REQUEST_FIELD to "1"))
            assertEquals("400", h[":status"])
            val e = assertFailsWith<Http3Exception.Settings> { session.getOrThrow() }
            assertTrue("webtransport-h3" in e.message.orEmpty(), e.message)
        }

    /**
     * draft-17 section 3.1: "SETTINGS_WT_ENABLED has no meaning when sent by a client; a server MUST ignore it" (the
     * draft exception of section 7.1 reads only a 1 as a version): a client's 2 is no connection error and names no
     * version, so its draft-16 setting decides.
     */
    @Test fun negative_serverIgnoresAClientsDraft17ValueAboveOne() =
        h3Test {
            val (h, session) = serve(listOf(SettingsId.WT_ENABLED_DRAFT17 to 2L, SettingsId.WT_ENABLED_DRAFT16 to 1L), WtTokens.H3)
            assertEquals("200", h[":status"])
            assertEquals(WtVersion.Draft16, session.getOrThrow().version)
        }

    /**
     * draft-16 binds only clients too ("Clients MUST treat values greater than "1" as a connection error"): a server takes
     * a client's draft-16 value of 2 as no version and no error, and selects from the rest of its SETTINGS.
     */
    @Test fun negative_serverIgnoresAClientsDraft16ValueAboveOne() =
        h3Test {
            val (h, session) = serve(listOf(SettingsId.WT_ENABLED_DRAFT16 to 2L, SettingsId.WT_ENABLED_DRAFT17 to 1L), WtTokens.H3)
            assertEquals("200", h[":status"])
            assertEquals(WtVersion.Draft17, session.getOrThrow().version)
        }

    /**
     * A client that sends draft-17's codepoint with 0 names no version (0 is the setting's default, "the server does not
     * support WebTransport"), so section 7.1's last branch selects draft-17.
     */
    @Test fun clientWithDraft17SettingZeroGetsDraft17() =
        h3Test {
            val (h, session) = serve(listOf(SettingsId.WT_ENABLED_DRAFT17 to 0L), WtTokens.H3)
            assertEquals("200", h[":status"])
            assertEquals(WtVersion.Draft17, session.getOrThrow().version)
        }

    /**
     * A client without WebTransport does not interpret the WebTransport settings: RFC 9114 section 7.2.4, "Endpoints MUST
     * ignore any settings with identifiers they do not understand". A server's `SETTINGS_WT_ENABLED` of 2, draft-17's or
     * draft-16's, is no error for it.
     */
    @Test fun negative_aClientWithoutWebTransportIgnoresWtEnabledAboveOne() =
        h3Test {
            for (id in listOf(SettingsId.WT_ENABLED_DRAFT17, SettingsId.WT_ENABLED_DRAFT16)) {
                QuicPair.open(H3Fixtures.quic).useScoped { q ->
                    val (c, s) = q.connect(H3Fixtures.quic)
                    RawPeer(s).openControl(listOf(id to 2L))
                    val client = Http3Connection.client(c, http3Settings { })
                    // applied without an error: the settings reach the application
                    val ps = withTimeout(5.seconds) { client.peerSettings.filterNotNull().first() }
                    assertTrue(!ps.webTransport, "0x${id.toString(16)}")
                    assertTrue(!client.closed.isCompleted, "0x${id.toString(16)}")
                }
            }
        }

    /** A server without WebTransport selects no version, not even section 7.1's draft-17 for a client that names none. */
    @Test fun negative_aServerWithoutWebTransportSelectsNoVersion() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val server = Http3Connection.server(s, http3Settings { enableConnectProtocol = true })
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                withTimeout(5.seconds) { server.peerSettings.filterNotNull().first() }
                assertNull(server.session.highestCommonWtVersion())
            }
        }

    /** draft-17 section 3.1: "Clients MUST treat values greater than "1" as a connection error of type H3_SETTINGS_ERROR". */
    @Test fun negative_draft17SettingAboveOneFromTheServerIsSettingsError() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                RawPeer(s).openControl(listOf(SettingsId.WT_ENABLED_DRAFT17 to 2L))
                runCatching { Http3Connection.client(c, wtOn) } // may already fail with the error it sent
                assertEquals(Http3ErrorCode.SETTINGS_ERROR, withTimeout(5.seconds) { peerSawClose(s) })
            }
        }

    /**
     * Every server draft our client offers gets a CONNECT of its own draft: `webtransport-h3` without the draft-02 field
     * for draft-17 and draft-16, `webtransport` with it for draft-02 (draft-17 section 7.1 "The highest version supported
     * by both endpoints is selected").
     */
    @Test fun eachDraftServerGetsACONNECTOfItsDraft() =
        h3Test {
            for (d in drafts.filter { it.version in WtVersion.ours(isServer = false) }) {
                QuicPair.open(H3Fixtures.quic).useScoped { q ->
                    val (c, s) = q.connect(H3Fixtures.quic)
                    val raw = RawPeer(s)
                    raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L, SettingsId.H3_DATAGRAM to 1L) + d.settings)
                    val client = Http3Connection.client(c, wtOn)
                    val session = async { client.webTransport(wtReq()) }
                    val st = withTimeout(5.seconds) { s.acceptBidi() }
                    val h = readHeaders(st)
                    assertEquals(d.token, h[":protocol"], "$d")
                    assertEquals(if (d.version == WtVersion.Draft02) "1" else null, h[WtTokens.DRAFT02_REQUEST_FIELD], "$d")
                    st.output.writeFully(raw.headers(st.id, listOf(":status" to "200")))
                    st.output.flush()
                    assertEquals(d.version, (withTimeout(5.seconds) { session.await() } as WtSessionImpl).version, "$d")
                }
            }
        }

    /** Our client and server both speak every version: they select draft-17 and announce draft-17, -16 and -02 (client). */
    @Test fun ourClientAndServerSelectDraft17() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                assertEquals(WtVersion.Draft17, (client as WtSessionImpl).version)
                assertEquals(WtVersion.Draft17, (server as WtSessionImpl).version)
                assertNull(server.headers[WtTokens.DRAFT02_REQUEST_FIELD])
                val ps =
                    withTimeout(5.seconds) {
                        p.server.peerSettings
                            .filterNotNull()
                            .first()
                    }
                assertTrue(ps.webTransport)
            }
        }

    /**
     * draft-17 section 4.3: WT_STREAM "in any other circumstances MUST be treated as a connection error of type
     * H3_FRAME_UNEXPECTED" (draft-16 and draft-14: H3_FRAME_ERROR). The connection's version decides: the signal on the
     * control stream, and inside a request stream after its HEADERS, of a draft-17 client and of a draft-16 one.
     */
    @Test fun negative_misplacedWtStreamSignalIsTheCodeOfTheConnectionsDraft() =
        h3Test {
            for ((setting, code) in listOf(
                SettingsId.WT_ENABLED_DRAFT17 to Http3ErrorCode.FRAME_UNEXPECTED,
                SettingsId.WT_ENABLED_DRAFT16 to Http3ErrorCode.FRAME_ERROR,
            )) {
                for (onControl in listOf(true, false)) {
                    QuicPair.open(H3Fixtures.quic).useScoped { q ->
                        val (c, s) = q.connect(H3Fixtures.quic)
                        val server = Http3Connection.server(s, wtOn)
                        val raw = RawPeer(c)
                        val control = raw.openControl(listOf(SettingsId.H3_DATAGRAM to 1L, setting to 1L))
                        // the SETTINGS are applied before the signal is read: the version is known by then
                        withTimeout(5.seconds) { server.peerSettings.filterNotNull().first() }
                        val signal = VarInt.encode(FrameType.WT_STREAM) + VarInt.encode(0)
                        // the request's body is read, so the frame after its HEADERS is
                        if (!onControl) launch { runCatching { server.acceptRequest().body.readAllBytes() } }
                        val st = if (onControl) control else c.openBidi()
                        // the server may close the connection before our flush returns
                        peerMayHaveClosed {
                            st.output.writeFully(if (onControl) signal else raw.headers(st.id, GET) + signal)
                            st.output.flush()
                        }
                        assertEquals(code, withTimeout(5.seconds) { peerSawClose(c) }, "0x${setting.toString(16)} control $onControl")
                    }
                }
            }
        }
}
