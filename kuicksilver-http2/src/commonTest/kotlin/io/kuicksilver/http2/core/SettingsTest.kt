// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.SettingId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SettingsTest {
    private fun settings(vararg kv: Pair<Int, Long>) =
        FrameEncoder.settings(kv.map { it.first }.toIntArray(), kv.map { it.second }.toLongArray())

    @Test
    fun negative_headerListSizeThatWouldOverflowIsRejected() {
        // twice the limit is buffered for a field block: a limit whose double overflows an Int is refused up front
        kotlin.test.assertFailsWith<IllegalArgumentException> { Http2Settings(maxHeaderListSize = Int.MAX_VALUE) }
        Http2Settings(maxHeaderListSize = Int.MAX_VALUE / 2)
    }

    @Test
    fun ackSent() {
        val peer = RawH2Peer(Role.SERVER)
        val out = peer.handshake(settings(SettingId.MAX_CONCURRENT_STREAMS to 7, 0x99 to 1)) // an unknown setting is ignored
        assertEquals(1, out.filterIsInstance<Frame.Settings>().count { it.ack }) // section 6.5.3
        assertTrue(H2Event.SettingsChanged in peer.events())
        assertEquals(7L, peer.core.peerMaxConcurrentStreams)
    }

    @Test
    fun negative_settingsAckTimeoutIsSettingsTimeout() {
        val peer = RawH2Peer(Role.SERVER)
        peer.send(io.kuicksilver.http2.frame.H2.PREFACE, settings()) // the client never acknowledges ours
        assertEquals(null, peer.core.nextTimeout()) // the deadline counts from when our SETTINGS were written
        peer.read()
        assertEquals(10 * SECOND, peer.core.nextTimeout())
        peer.core.onTimeout(10 * SECOND - 1)
        assertEquals(false, peer.core.isClosed)
        peer.core.onTimeout(10 * SECOND)
        peer.assertConnectionError(Http2ErrorCode.SETTINGS_TIMEOUT) // section 6.5.3, code 0x4
        // acknowledged in time: no deadline left
        val ok = RawH2Peer(Role.SERVER)
        ok.handshake()
        assertEquals(null, ok.core.nextTimeout())
    }

    @Test
    fun negative_enablePushFromServerIsProtocolError() {
        val c = RawH2Peer(Role.CLIENT)
        c.send(settings(SettingId.ENABLE_PUSH to 1)) // section 6.5.2: a server never sends 1
        c.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
        val zero = RawH2Peer(Role.CLIENT)
        zero.handshake(settings(SettingId.ENABLE_PUSH to 0))
        assertEquals(false, zero.core.isClosed)
        val s = RawH2Peer(Role.SERVER)
        s.handshake(settings(SettingId.ENABLE_PUSH to 2)) // neither 0 nor 1
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun negative_maxFrameSizeOutOfRange() {
        for (v in listOf(16_383L, 16_777_216L)) {
            val s = RawH2Peer(Role.SERVER)
            s.handshake(settings(SettingId.MAX_FRAME_SIZE to v))
            s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // section 6.5.2
        }
        for (v in listOf(16_384L, 16_777_215L)) {
            val s = RawH2Peer(Role.SERVER)
            s.handshake(settings(SettingId.MAX_FRAME_SIZE to v))
            assertEquals(false, s.core.isClosed)
        }
    }

    @Test
    fun negative_initialWindowSizeAboveMaximumIsFlowControlError() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake(settings(SettingId.INITIAL_WINDOW_SIZE to 2_147_483_648))
        s.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR) // section 6.5.2
    }

    /**
     * RFC 8441 section 3: a server that accepts Extended CONNECT says so with SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 in its
     * SETTINGS; without it the parameter is not sent at all (its initial value, 0, holds). A client never sends it.
     */
    @Test
    fun extendedConnectAdvertisedOnlyWhenEnabled() {
        fun sent(
            role: Role,
            enabled: Boolean,
        ): Long? {
            val p = RawH2Peer(role, enableConnectProtocol = enabled)
            val ours = p.handshake().filterIsInstance<Frame.Settings>().first { !it.ack }
            return ours.ids
                .indexOf(SettingId.ENABLE_CONNECT_PROTOCOL)
                .takeIf { it >= 0 }
                ?.let { ours.values[it] }
        }
        assertEquals(1L, sent(Role.SERVER, enabled = true))
        assertEquals(null, sent(Role.SERVER, enabled = false))
        assertEquals(null, sent(Role.CLIENT, enabled = false))
        assertFailsWith<IllegalArgumentException> { H2ConnectionCore(Role.CLIENT, Http2Settings(), 0, enableConnectProtocol = true) }
    }

    /**
     * RFC 8441 section 3: "A sender MUST NOT send a SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with the value of 0 after
     * previously sending a value of 1." A client that sees a server take it back ends the connection with PROTOCOL_ERROR
     * (as nghttp2 does): the Extended CONNECT streams it may have opened meanwhile would otherwise be malformed. A server is
     * not affected by the parameter ("Receipt of this parameter by a server does not have any impact").
     */
    @Test
    fun negative_serverWithdrawingExtendedConnectIsAProtocolError() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        c.send(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 0))
        c.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)

        val again = RawH2Peer(Role.CLIENT)
        again.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        again.send(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1)) // the same value again is fine
        assertEquals(false, again.core.isClosed)
        assertTrue(again.core.peerEnableConnectProtocol)

        val s = RawH2Peer(Role.SERVER)
        s.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        s.send(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 0))
        s.read()
        assertEquals(false, s.core.isClosed)
    }

    @Test
    fun negative_booleanSettingsOtherThanZeroOrOne() {
        for (id in listOf(SettingId.ENABLE_CONNECT_PROTOCOL, SettingId.NO_RFC7540_PRIORITIES)) {
            val s = RawH2Peer(Role.SERVER)
            s.handshake(settings(id to 2)) // RFC 8441 section 3, RFC 9218 section 2.1
            s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
        }
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        assertTrue(c.core.peerEnableConnectProtocol)
    }

    @Test
    fun peerMaxConcurrentStreamsRespected() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.MAX_CONCURRENT_STREAMS to 1))
        val first = c.core.openStream(GET, endStream = true)
        assertFailsWith<H2StreamLimit> { c.core.openStream(GET, endStream = true) } // the engine waits or opens another connection
        c.read()
        c.send(c.headers(first, OK, endStream = true))
        assertEquals(3, c.core.openStream(GET, endStream = true)) // the first is closed: room again
    }

    @Test
    fun peerHeaderListSizeHonouredWhenSending() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.MAX_HEADER_LIST_SIZE to 200))
        assertFailsWith<H2HeaderListTooLarge> { c.core.openStream(GET + ("x-big" to "v".repeat(200)), endStream = true) }
        // nothing was sent and the HPACK state did not move: the next request decodes on the peer's side
        val id = c.core.openStream(GET, endStream = true)
        val h = c.read().filterIsInstance<Frame.Headers>().single()
        assertEquals(id, h.streamId)
        assertEquals(GET, c.decodeBlock(h.fragment))
    }

    @Test
    fun peerHeaderTableSizeZeroSentAsUpdate() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.HEADER_TABLE_SIZE to 0))
        c.core.openStream(GET + ("x-a" to "1"), endStream = true)
        val h = c.read().filterIsInstance<Frame.Headers>().single()
        assertEquals(0x20, h.fragment[0].toInt() and 0xff) // RFC 7541 section 4.2: an update to 0 first
        assertEquals(GET + ("x-a" to "1"), c.decodeBlock(h.fragment))
    }

    @Test
    fun largeFieldSectionSplitIntoContinuationFrames() {
        val p = H2Pair()
        val fields = GET + (1..40).map { "x-h$it" to "v".repeat(1_000) } // about 40 KiB: HEADERS + CONTINUATION frames
        val id = p.client.openStream(fields, endStream = true)
        p.pump()
        val h = p.serverGot<H2Event.HeadersReceived>().single()
        assertEquals(id, h.streamId)
        assertEquals(fields, h.fields)
    }

    @Test
    fun ourSmallerSettingsTakeEffectWhenAcknowledged() {
        // a 1000-byte stream window: until our SETTINGS are acknowledged the peer may use the protocol's 65 535
        val s = RawH2Peer(Role.SERVER, Http2Settings(initialStreamWindow = 1_000))
        s.send(io.kuicksilver.http2.frame.H2.PREFACE, settings())
        s.send(s.headers(1, endStream = false), s.data(1, 5_000))
        assertEquals(false, s.core.isClosed)
        assertTrue(s.resets().isEmpty())
        s.send(FrameEncoder.settingsAck()) // now 1000 holds: 5 000 already sent puts the stream 4 000 over
        s.send(s.data(1, 1))
        s.assertStreamError(1, Http2ErrorCode.FLOW_CONTROL_ERROR)
    }
}
