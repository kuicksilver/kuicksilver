// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.DelicateKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.MemoryNet
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.acceptBidi
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerSawClose
import io.kuicksilver.http3.runtime.readControlFrame
import io.kuicksilver.http3.runtime.readVarInt
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** WebTransport settings with Extended CONNECT and HTTP datagrams, as both sides of a WebTransport test use them. */
internal val wtOn: Http3Settings =
    http3Settings {
        enableConnectProtocol = true
        webTransport = true
    }

/** The SETTINGS the peer of [q] sent on its control stream. */
internal suspend fun peerSettingsOf(q: QuicConnection): Map<Long, Long> {
    val control: QuicStream =
        withTimeout(5.seconds) {
            while (true) {
                val st = q.acceptStream()
                if (st.id and 2L != 0L && st.readVarInt() == StreamType.CONTROL) return@withTimeout st
            }
            @Suppress("UNREACHABLE_CODE")
            null!!
        }
    val (t, payload) = control.readControlFrame()
    assertEquals(FrameType.SETTINGS, t)
    return SettingsCodec.decode(payload)
}

class WebTransportSettingsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** draft-ietf-webtrans-http3-16 section 3.1 and the codepoints browsers still use (draft-02, draft-14). */
    @Test fun serverAdvertisesAllWtCodepoints() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                Http3Connection.server(s, wtOn)
                val m = peerSettingsOf(c)
                assertEquals(1L, m[SettingsId.ENABLE_WEBTRANSPORT_DRAFT02])
                assertEquals(1L, m[SettingsId.WT_MAX_SESSIONS_DRAFT14])
                assertEquals(1L, m[SettingsId.WT_ENABLED])
                assertEquals(1L, m[SettingsId.ENABLE_CONNECT_PROTOCOL])
                assertEquals(1L, m[SettingsId.H3_DATAGRAM])
                // no WebTransport flow control: one session per connection (section 5.1)
                for (k in listOf(0x2b61L, 0x2b64L, 0x2b65L)) assertNull(m[k], "0x${k.toString(16)}")
            }
        }

    @Test fun clientAdvertisesWtEnabled() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val raw = RawPeer(s)
                raw.openControl()
                Http3Connection.client(c, wtOn)
                val m = peerSettingsOf(s)
                assertEquals(1L, m[SettingsId.WT_ENABLED])
                assertEquals(1L, m[SettingsId.ENABLE_WEBTRANSPORT_DRAFT02])
            }
        }

    @Test fun wtSettingsNotSentByDefault() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                Http3Connection.server(s, http3Settings { enableConnectProtocol = true })
                val m = peerSettingsOf(c)
                for (k in listOf(SettingsId.WT_ENABLED, SettingsId.WT_MAX_SESSIONS_DRAFT14, SettingsId.ENABLE_WEBTRANSPORT_DRAFT02)) {
                    assertNull(m[k], "0x${k.toString(16)}")
                }
            }
        }

    /** Section 3.1: SETTINGS_WT_ENABLED other than 0 or 1 is H3_SETTINGS_ERROR. */
    @Test fun negative_wtEnabledAboveOneIsSettingsError() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.WT_ENABLED to 2L))
                runCatching { Http3Connection.client(c, wtOn) } // may already fail with the error it sent
                assertEquals(Http3ErrorCode.SETTINGS_ERROR, withTimeout(5.seconds) { peerSawClose(s) })
            }
        }

    /** draft-02 section 3.1: "an endpoint that receives a value other than "0" or "1" MUST close the connection with the H3_SETTINGS_ERROR". */
    @Test fun negative_draft02SettingAboveOneIsSettingsError() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 2L))
                runCatching { Http3Connection.client(c, wtOn) } // may already fail with the error it sent
                assertEquals(Http3ErrorCode.SETTINGS_ERROR, withTimeout(5.seconds) { peerSawClose(s) })
            }
        }

    /**
     * Draft-16 section 7.1: "The highest version supported by both endpoints is selected". Our client announces draft-16 and
     * draft-02, so against a server of draft-14 and draft-02 it speaks draft-02, never the draft-14 it did not offer.
     */
    @Test fun peerVersionIsTheHighestBothAnnounce() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L, SettingsId.WT_MAX_SESSIONS_DRAFT14 to 1L))
                val client = Http3Connection.client(c, wtOn)
                val ps = withTimeout(5.seconds) { client.peerSettings.filterNotNull().first() }
                assertTrue(ps.webTransport)
                assertEquals(WtVersion.Draft02, client.session.highestCommonWtVersion())
                // interpreted codepoints are not reported as unknown
                assertFalse(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 in ps.unknown)
                assertFalse(SettingsId.WT_MAX_SESSIONS_DRAFT14 in ps.unknown)
            }
        }

    /** A server of draft-14 alone has no version in common with our client: no session, no CONNECT. */
    @Test fun negative_clientNeverPicksADraftItDidNotOffer() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                RawPeer(s).openControl(
                    listOf(
                        SettingsId.ENABLE_CONNECT_PROTOCOL to 1L,
                        SettingsId.H3_DATAGRAM to 1L,
                        SettingsId.WT_MAX_SESSIONS_DRAFT14 to 1L,
                    ),
                )
                val client = Http3Connection.client(c, wtOn)
                assertFailsWith<Http3Exception.Settings> { client.webTransport(wtReq()) }
                assertNull(client.session.highestCommonWtVersion())
            }
        }

    /**
     * A server of draft-14 and draft-02 without `reset_stream_at` cannot run draft-14 (section 3.1) but can run draft-02:
     * the client sends a draft-02 CONNECT (before, it chose draft-14, which it never offered).
     */
    @Test fun draft14And02ServerWithoutResetStreamAtGetsADraft02Connect() =
        h3Test {
            QuicPair.open(QuicConfig.Default).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                RawPeer(s).openControl(
                    listOf(
                        SettingsId.ENABLE_CONNECT_PROTOCOL to 1L,
                        SettingsId.H3_DATAGRAM to 1L,
                        SettingsId.WT_MAX_SESSIONS_DRAFT14 to 1L,
                        SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L,
                    ),
                )
                val client = Http3Connection.client(c, wtOn)
                val call = async { runCatching { client.webTransport(wtReq()) } }
                val st = withTimeout(5.seconds) { s.acceptBidi() }
                val h = readHeaders(st)
                assertEquals(WtTokens.LEGACY, h[":protocol"])
                assertEquals("1", h[WtTokens.DRAFT02_REQUEST_FIELD])
                call.cancel()
            }
        }

    @Test fun peerWithoutWtHasNoVersion() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                RawPeer(s).openControl(listOf(SettingsId.WT_MAX_SESSIONS_DRAFT14 to 0L))
                val client = Http3Connection.client(c, wtOn)
                val ps = withTimeout(5.seconds) { client.peerSettings.filterNotNull().first() }
                assertFalse(ps.webTransport)
                assertNull(client.session.highestCommonWtVersion())
            }
        }

    @Test fun webTransportRequiresConnectAndDatagram() {
        assertFailsWith<IllegalArgumentException> {
            http3Settings {
                enableConnectProtocol = true
                h3Datagram = false
                webTransport = true
            }
        }
        assertFailsWith<IllegalArgumentException> { http3Settings { webTransport = true } }
        assertTrue(wtOn.toBuilder().build().webTransport)
    }

    /** WebTransport carries HTTP datagrams: a server without QUIC datagrams refuses it instead of quietly dropping them. */
    @Test fun negative_webTransportWithoutQuicDatagramsRefused() =
        h3Test {
            val config =
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server =
                            QuicServerConfig.Builder(H3Fixtures.server()).apply { quic = quicConfig { maxDatagramFrameSize = 0 } }.build()
                    }.build()
            val e = assertFailsWith<IllegalArgumentException> { Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0), config, wtOn) }
            assertTrue("maxDatagramFrameSize" in e.message.orEmpty(), e.message)
        }

    /**
     * Section 3.1: WebTransport needs `reset_stream_at` on both sides, so `Http3Endpoint` turns `QuicConfig.resetStreamAt`
     * on with `webTransport` (as the Ktor engines do): a session between two endpoints left at the defaults works.
     */
    @Test fun endpointTurnsResetStreamAtOnForWebTransport(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val net = MemoryNet()
                val serverIo = net.open(InetSocketAddress("10.0.0.2", 443))
                val clientIo = net.open(InetSocketAddress("10.0.0.1", 1111))
                val server =
                    Http3Endpoint.bind(
                        serverIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(H3Fixtures.server()).build()
                                crypto = NullCryptoProvider
                                io = { serverIo }
                            }.build(),
                        wtOn,
                    )
                val client =
                    Http3Endpoint.bind(
                        clientIo.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                io = { clientIo }
                            }.build(),
                    )
                try {
                    coroutineScope {
                        val accepted = async { server.accept() }
                        val conn = client.connect(server.localAddress, H3Fixtures.client(), settings = wtOn)
                        val serverConn = accepted.await()
                        launch { serverConn.acceptRequest().acceptWebTransport() }
                        val session = conn.webTransport(wtReq())
                        assertTrue(conn.quic.resetStreamAtEnabled)
                        assertTrue(serverConn.quic.resetStreamAtEnabled)
                        session.close()
                        conn.close()
                    }
                } finally {
                    client.close()
                    server.close()
                }
            }
        }

    /** Section 3.2: a ticket issued without WebTransport gives no 0-RTT to a server that now has it, and back. */
    @Test fun earlyDataContextCoversWebTransport() {
        val off = http3Settings { enableConnectProtocol = true }
        assertNotEquals(off.earlyDataContext().decodeToString(), wtOn.earlyDataContext().decodeToString())
    }
}
