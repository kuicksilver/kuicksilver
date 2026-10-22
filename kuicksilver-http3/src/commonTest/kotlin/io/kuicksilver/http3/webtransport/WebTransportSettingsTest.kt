// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerSawClose
import io.kuicksilver.http3.runtime.readControlFrame
import io.kuicksilver.http3.runtime.readVarInt
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
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
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
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
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
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
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
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
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.WT_ENABLED to 2L))
                runCatching { Http3Connection.client(c, wtOn) } // may already fail with the error it sent
                assertEquals(Http3ErrorCode.SETTINGS_ERROR, withTimeout(5.seconds) { peerSawClose(s) })
            }
        }

    @Test fun peerVersionPicksHighest() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L, SettingsId.WT_MAX_SESSIONS_DRAFT14 to 1L))
                val client = Http3Connection.client(c, wtOn)
                val ps = withTimeout(5.seconds) { client.peerSettings.filterNotNull().first() }
                assertTrue(ps.webTransport)
                assertEquals(WtVersion.Draft14, client.session.peerWtVersion())
                // interpreted codepoints are not reported as unknown
                assertFalse(SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 in ps.unknown)
                assertFalse(SettingsId.WT_MAX_SESSIONS_DRAFT14 in ps.unknown)
            }
        }

    @Test fun peerWithoutWtHasNoVersion() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                RawPeer(s).openControl(listOf(SettingsId.WT_MAX_SESSIONS_DRAFT14 to 0L))
                val client = Http3Connection.client(c, wtOn)
                val ps = withTimeout(5.seconds) { client.peerSettings.filterNotNull().first() }
                assertFalse(ps.webTransport)
                assertNull(client.session.peerWtVersion())
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

    /** Section 3.2: a ticket issued without WebTransport gives no 0-RTT to a server that now has it, and back. */
    @Test fun earlyDataContextCoversWebTransport() {
        val off = http3Settings { enableConnectProtocol = true }
        assertNotEquals(off.earlyDataContext().decodeToString(), wtOn.earlyDataContext().decodeToString())
    }
}
