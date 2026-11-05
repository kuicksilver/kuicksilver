// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.FrameFlags
import io.kuicksilver.http2.frame.FrameType
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.SettingId
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class StreamStateTest {
    @Test
    fun requestResponseWalksTheStatesOfSection51() {
        val p = H2Pair()
        val id = p.client.openStream(GET, endStream = false) // idle -> open
        assertEquals(1, id)
        assertEquals(1, p.client.sendData(id, byteArrayOf(7), 0, 1, endStream = true)) // open -> half-closed (local)
        p.pump()
        val req = p.serverGot<H2Event.HeadersReceived>().single()
        assertEquals(GET, req.fields)
        assertEquals(false, req.endStream)
        val body = p.serverGot<H2Event.Data>().single()
        assertTrue(body.endStream) // server: open -> half-closed (remote)
        p.server.sendHeaders(id, OK, endStream = false)
        assertEquals(2, p.server.sendData(id, "hi".encodeToByteArray(), 0, 2, endStream = true)) // half-closed (remote) -> closed
        p.pump()
        val resp = p.clientGot<H2Event.HeadersReceived>().single()
        assertEquals(OK, resp.fields)
        val d = p.clientGot<H2Event.Data>().single()
        assertContentEquals("hi".encodeToByteArray(), d.data)
        assertTrue(d.endStream) // client: half-closed (local) -> closed
        assertEquals(1, p.client.activeStreams) // until the driver is done with it
        p.client.release(id)
        assertEquals(0, p.client.activeStreams)
        assertEquals(1, p.server.activeStreams) // its handler still runs
        p.server.release(id)
        assertEquals(0, p.server.activeStreams)
        assertEquals(3, p.client.openStream(GET, endStream = true)) // the next client identifier
    }

    /**
     * RFC 9113 section 8.1: a server MAY ask the client to stop sending a request with RST_STREAM NO_ERROR after a complete
     * response. Once the handler is done (release) with the request still open, the core does so after the response's
     * last frame (as Go's server.go wroteFrame), so a client cannot keep a released stream busy with content nobody reads.
     */
    @Test
    fun releasedRequestStillSendingIsStoppedWithNoErrorAfterTheResponse() {
        val p = H2Pair()
        val id = p.client.openStream(GET + ("content-length" to "100"), endStream = false)
        p.client.sendData(id, ByteArray(10), 0, 10, endStream = false)
        p.pump()
        p.server.sendHeaders(id, OK, endStream = false)
        p.server.sendData(id, "done".encodeToByteArray(), 0, 4, endStream = true) // half-closed (local)
        p.server.release(id) // the handler is done; the client still sends
        p.pump()
        val reset = p.clientGot<H2Event.StreamReset>().single()
        assertEquals(Http2ErrorCode.NO_ERROR, reset.code)
        // the response was complete before the reset (the frames went out in order)
        assertTrue(p.clientGot<H2Event.Data>().single().endStream)
        assertEquals(0, p.server.activeStreams)
    }

    /** A handler still reading the request (not released) is not cut off by its own complete response. */
    @Test
    fun completeResponseBeforeReleaseLeavesTheRequestOpen() {
        val p = H2Pair()
        val id = p.client.openStream(GET, endStream = false)
        p.pump()
        p.server.sendHeaders(id, OK, endStream = true)
        p.pump()
        assertTrue(p.clientGot<H2Event.StreamReset>().isEmpty())
        assertEquals(1, p.client.sendData(id, byteArrayOf(1), 0, 1, endStream = true))
        p.pump()
        assertTrue(p.serverGot<H2Event.Data>().single().endStream)
    }

    /**
     * RFC 9113 section 5.4.2: an endpoint MUST NOT send a RST_STREAM in response to a RST_STREAM; section 5.1: nothing but
     * PRIORITY goes out on a closed stream. The driver's reset of a stream the peer reset, or that ended both ways, sends
     * nothing.
     */
    @Test
    fun negative_noResetOfAStreamThePeerResetOrThatEnded() {
        val p = RawH2Peer(Role.SERVER)
        p.handshake()
        p.send(p.headers(1, endStream = false), p.headers(3, endStream = true))
        p.send(FrameEncoder.rstStream(1, Http2ErrorCode.CANCEL.code))
        p.core.sendHeaders(3, OK, endStream = true) // 3 ends both ways
        p.read()
        p.core.reset(1, Http2ErrorCode.INTERNAL_ERROR, p.now)
        p.core.reset(3, Http2ErrorCode.INTERNAL_ERROR, p.now)
        p.core.release(1)
        p.core.release(3)
        p.read()
        assertEquals(emptyList(), p.resets().map { it.streamId }, "no RST_STREAM after the peer's, none on an ended stream")
    }

    @Test
    fun interimResponsesThenFinalThenTrailers() {
        val p = H2Pair()
        val id = p.client.openStream(GET, endStream = true)
        p.pump()
        p.server.sendHeaders(id, listOf(":status" to "103", "link" to "</s.css>"), endStream = false)
        p.server.sendHeaders(id, OK, endStream = false)
        p.server.sendData(id, byteArrayOf(1), 0, 1, endStream = false)
        p.server.sendHeaders(id, listOf("x-checksum" to "1"), endStream = true)
        p.pump()
        val h = p.clientGot<H2Event.HeadersReceived>()
        assertEquals(listOf("103", "200"), h.take(2).map { it.fields[0].second })
        assertEquals(listOf("x-checksum" to "1"), h[2].fields)
        assertTrue(h[2].endStream)
        p.client.release(id)
        assertEquals(0, p.client.activeStreams)
    }

    @Test
    fun negative_dataOnClosedStreamIsStreamClosed() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        peer.send(peer.headers(1, endStream = true)) // the request is complete: half-closed (remote)
        peer.send(peer.data(1, 3))
        peer.assertStreamError(1, Http2ErrorCode.STREAM_CLOSED) // section 5.1, half-closed (remote)
        // a stream the peer reset is closed: DATA on it is STREAM_CLOSED too (section 6.1)
        peer.send(peer.headers(3, endStream = false), FrameEncoder.rstStream(3, Http2ErrorCode.CANCEL.code), peer.data(3, 1))
        peer.assertStreamError(3, Http2ErrorCode.STREAM_CLOSED)
        // and its DATA still counted toward the connection window: no FLOW_CONTROL_ERROR, credit came back
        assertEquals(false, peer.core.isClosed)
        // a closed stream we no longer remember (one of many): DATA on it is still STREAM_CLOSED (section 6.1)
        val many = RawH2Peer(Role.SERVER)
        many.handshake()
        for (i in 0 until 600) {
            val id = 1 + 2 * i
            many.send(many.headers(id, endStream = true))
            many.core.sendHeaders(id, OK, endStream = true)
            many.core.release(id)
            many.read()
        }
        many.send(many.data(1, 1))
        many.assertStreamError(1, Http2ErrorCode.STREAM_CLOSED)
    }

    /**
     * RFC 9113 section 5.1, "closed": an endpoint MAY treat a frame on a closed stream as a connection error of type
     * STREAM_CLOSED (RFC 7540 made it a MUST after END_STREAM both ways; h2spec http2/5.1/12 checks it). A HEADERS frame on a
     * stream that ended both ways (released or still held by its handler) or that the peer reset ends the connection.
     */
    @Test
    fun negative_headersOnAClosedStreamIsAConnectionError() {
        for (held in listOf(false, true)) {
            val p = RawH2Peer(Role.SERVER)
            p.handshake()
            p.send(p.headers(1, endStream = true))
            p.core.sendHeaders(1, OK, endStream = true) // closed both ways
            if (!held) p.core.release(1)
            p.read()
            p.send(p.headers(1, endStream = true))
            p.assertConnectionError(Http2ErrorCode.STREAM_CLOSED)
        }
        val reset = RawH2Peer(Role.SERVER)
        reset.handshake()
        reset.send(reset.headers(1, endStream = false), FrameEncoder.rstStream(1, Http2ErrorCode.CANCEL.code))
        reset.core.release(1)
        reset.send(reset.headers(1, endStream = true))
        reset.assertConnectionError(Http2ErrorCode.STREAM_CLOSED)
        // the same rule on a client: a second response on a stream that ended both ways
        val client = RawH2Peer(Role.CLIENT)
        client.handshake()
        val id = client.core.openStream(GET, endStream = true)
        client.read()
        client.send(client.headers(id, OK, endStream = true))
        client.core.release(id)
        client.send(client.headers(id, OK, endStream = true))
        client.assertConnectionError(Http2ErrorCode.STREAM_CLOSED)
    }

    @Test
    fun framesOnAStreamWeResetAreDiscarded() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        peer.send(peer.headers(1, endStream = false))
        peer.core.reset(1, Http2ErrorCode.CANCEL, 0)
        peer.read()
        val before = peer.resets().size
        // section 5.1: frames the peer sent before it saw our RST_STREAM are processed minimally, without another reset
        peer.send(peer.data(1, 100), peer.headers(1, listOf("x-t" to "1"), endStream = true), FrameEncoder.windowUpdate(1, 10))
        peer.read()
        assertEquals(before, peer.resets().size)
        assertEquals(false, peer.core.isClosed)
    }

    @Test
    fun negative_noResetOnIdleStream() {
        // section 6.4: RST_STREAM MUST NOT be sent for an idle stream, whatever the driver asks
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        c.core.reset(1, Http2ErrorCode.CANCEL, 0) // never opened
        c.core.reset(2, Http2ErrorCode.CANCEL, 0) // a server's identifier
        assertEquals(emptyList(), c.read().filterIsInstance<Frame.RstStream>())
    }

    @Test
    fun negative_resetBeforeTheHeadersAreWrittenSendsNothing() {
        // section 6.4: a stream whose HEADERS never left is idle to the peer: no RST_STREAM, and the request is retry-safe
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val a = c.core.openStream(GET, endStream = true)
        c.core.reset(a, Http2ErrorCode.CANCEL, 0)
        val r = c.events().only<H2Event.StreamReset>()
        assertEquals(a, r.streamId)
        assertTrue(r.notProcessed)
        val b = c.core.openStream(GET, endStream = true)
        val out = c.read()
        assertEquals(emptyList(), out.filterIsInstance<Frame.RstStream>())
        assertEquals(listOf(b), out.filterIsInstance<Frame.Headers>().map { it.streamId }) // b implicitly closes a (section 5.1.1)
        // after the HEADERS are written, a reset is a RST_STREAM
        c.core.reset(b, Http2ErrorCode.CANCEL, 0)
        assertEquals(listOf(b), c.read().filterIsInstance<Frame.RstStream>().map { it.streamId })
        // a connection error reports a request whose HEADERS were never written as not processed, a written one as maybe
        // processed
        val d = RawH2Peer(Role.CLIENT)
        d.handshake()
        val sent = d.core.openStream(GET, endStream = true)
        d.read()
        val queued = d.core.openStream(GET, endStream = true)
        d.send(FrameEncoder.raw(0x4, 0, 1, ByteArray(0))) // SETTINGS on a stream: PROTOCOL_ERROR
        val resets = d.events().filterIsInstance<H2Event.StreamReset>().associateBy { it.streamId }
        assertEquals(false, resets.getValue(sent).notProcessed)
        assertEquals(true, resets.getValue(queued).notProcessed)
    }

    @Test
    fun negative_streamErrorInsideAFieldBlockIsAConnectionError() {
        // sections 6.2, 6.10: HEADERS on 3 without END_HEADERS, then a PRIORITY of the wrong length on 1 (a stream error on
        // its own): inside a field block it is a connection PROTOCOL_ERROR
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(s.headers(1, endStream = false))
        val b = s.hpackOut.encode(GET)
        s.send(FrameEncoder.headers(3, b.copyOfRange(0, 2), endStream = true, endHeaders = false))
        s.send(FrameEncoder.raw(0x2, 0, 1, ByteArray(4)))
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun negative_status101IsMalformed() {
        // section 8.6: HTTP/2 does not support 101 (Switching Protocols)
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = true)
        c.read()
        c.send(c.headers(id, listOf(":status" to "101"), endStream = false))
        c.assertStreamError(id, Http2ErrorCode.PROTOCOL_ERROR)
        assertEquals(emptyList(), c.allEvents.filterIsInstance<H2Event.HeadersReceived>())
    }

    @Test
    fun negative_decoderTableStartsAt4096UntilOurSettingsAreAcknowledged() {
        // section 4.3.1: both tables start at 4096; our larger SETTINGS_HEADER_TABLE_SIZE holds only once acknowledged
        val s = RawH2Peer(Role.SERVER, io.kuicksilver.http2.Http2Settings(headerTableSize = 65_536))
        s.send(io.kuicksilver.http2.frame.H2.PREFACE, FrameEncoder.settings(IntArray(0), LongArray(0)))
        val update8192 = byteArrayOf(0x3f, 0xe1.toByte(), 0x3f, 0x82.toByte()) // a table size update to 8192, then :method GET
        s.send(FrameEncoder.headers(1, update8192, endStream = true, endHeaders = true))
        s.assertConnectionError(Http2ErrorCode.COMPRESSION_ERROR)
        val ok = RawH2Peer(Role.SERVER, io.kuicksilver.http2.Http2Settings(headerTableSize = 65_536))
        ok.handshake() // includes our ACK
        ok.send(FrameEncoder.headers(1, update8192, endStream = true, endHeaders = true))
        assertEquals(1, ok.events().filterIsInstance<H2Event.HeadersReceived>().size)
    }

    @Test
    fun pingAnswerGoesFirst() {
        // section 6.7: PING responses SHOULD be given higher priority than any other frame
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.core.ping(0)
        s.send(s.headers(1, endStream = false), FrameEncoder.ping(false, 42))
        s.core.reset(1, Http2ErrorCode.CANCEL, 0)
        val out = s.read()
        val first = out.first() as Frame.Ping
        assertTrue(first.ack)
        assertEquals(42L, first.payload)
    }

    @Test
    fun negative_evenStreamFromClientIsProtocolError() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        peer.send(peer.headers(2))
        peer.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // section 5.1.1
    }

    @Test
    fun negative_streamIdDecreasingIsProtocolError() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        peer.send(peer.headers(5))
        peer.send(peer.headers(3)) // 3 was implicitly closed by 5 (section 5.1.1)
        peer.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun negative_framesOnIdleStreamsAreProtocolErrors() {
        for (frame in listOf(
            FrameEncoder.data(1, ByteArray(1), 0, 1, false),
            FrameEncoder.rstStream(1, 0),
            FrameEncoder.windowUpdate(1, 1),
        )) {
            val peer = RawH2Peer(Role.SERVER)
            peer.handshake()
            peer.send(frame)
            peer.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // section 5.1, idle; section 6.4
        }
        // a client: HEADERS on a stream it never opened, or a server-initiated one (no push)
        for (id in listOf(1, 2)) {
            val peer = RawH2Peer(Role.CLIENT)
            peer.handshake()
            peer.send(peer.headers(id, OK))
            peer.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
        }
    }

    @Test
    fun priorityOnIdleStreamIsAllowedAndIgnored() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        peer.send(FrameEncoder.priority(9, 0)) // section 6.3: any state, idle included
        peer.send(peer.headers(3)) // 9 was not opened by PRIORITY: 3 is still a new stream
        assertEquals(3, peer.events().only<H2Event.HeadersReceived>().streamId)
        assertEquals(emptyList(), peer.read().filterIsInstance<Frame.GoAway>())
    }

    @Test
    fun negative_selfDependencyIsStreamError() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        peer.send(peer.headers(1, endStream = false, dependency = 1)) // section 5.3.1
        peer.assertStreamError(1, Http2ErrorCode.PROTOCOL_ERROR)
        peer.send(peer.headers(3, endStream = false), FrameEncoder.priority(3, 3))
        peer.assertStreamError(3, Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun negative_frameInsideFieldBlockIsProtocolError() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        val block = peer.hpackOut.encode(GET)
        peer.send(FrameEncoder.headers(1, block.copyOfRange(0, 2), endStream = true, endHeaders = false), FrameEncoder.ping(false, 1))
        peer.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // section 6.10
        val other = RawH2Peer(Role.SERVER)
        other.handshake()
        val b2 = other.hpackOut.encode(GET)
        other.send(
            FrameEncoder.headers(1, b2.copyOfRange(0, 2), true, false),
            FrameEncoder.continuation(3, b2.copyOfRange(2, b2.size), true),
        )
        other.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // a CONTINUATION of another stream
        val third = RawH2Peer(Role.SERVER)
        third.handshake()
        third.send(FrameEncoder.continuation(1, byteArrayOf(0x82.toByte()), true)) // CONTINUATION without HEADERS
        third.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
        val fourth = RawH2Peer(Role.SERVER)
        fourth.handshake()
        val b4 = fourth.hpackOut.encode(GET)
        fourth.send(FrameEncoder.headers(1, b4.copyOfRange(0, 2), true, false), FrameEncoder.raw(0xfa, 0, 0, ByteArray(1)))
        fourth.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // even an unknown frame type (section 6.10)
    }

    @Test
    fun fieldBlockSplitOverContinuationFrames() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        val block = peer.hpackOut.encode(GET + ("x-long" to "v".repeat(100)))
        peer.send(
            FrameEncoder.headers(1, block.copyOfRange(0, 10), endStream = true, endHeaders = false),
            FrameEncoder.continuation(1, block.copyOfRange(10, 50), false),
            FrameEncoder.continuation(1, block.copyOfRange(50, block.size), true),
        )
        assertEquals(GET + ("x-long" to "v".repeat(100)), peer.events().only<H2Event.HeadersReceived>().fields)
    }

    @Test
    fun negative_secondFieldSectionWithoutEndStreamIsMalformed() {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake()
        peer.send(peer.headers(1, endStream = false), peer.headers(1, listOf("x-t" to "1"), endStream = false))
        peer.assertStreamError(1, Http2ErrorCode.PROTOCOL_ERROR) // section 8.1: trailers carry END_STREAM
        // a client: an interim response with END_STREAM, and DATA before the final response
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val a = c.core.openStream(GET, true)
        val b = c.core.openStream(GET, true)
        c.read()
        c.send(c.headers(a, listOf(":status" to "100"), endStream = true))
        c.assertStreamError(a, Http2ErrorCode.PROTOCOL_ERROR)
        c.send(c.data(b, 1))
        c.assertStreamError(b, Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun negative_invalidPrefaceOrFirstFrame() {
        val peer = RawH2Peer(Role.SERVER)
        peer.send("GET / HTTP/1.1\r\n\r\n".encodeToByteArray())
        peer.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // section 3.4
        val second = RawH2Peer(Role.SERVER)
        second.send(H2.PREFACE, FrameEncoder.ping(false, 1))
        second.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // the preface ends with SETTINGS
        val client = RawH2Peer(Role.CLIENT)
        client.send(FrameEncoder.settingsAck())
        client.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // the server's first frame is SETTINGS (not an ACK)
    }

    @Test
    fun clientPrefaceAndSettings() {
        val peer = RawH2Peer(Role.SERVER)
        val c = H2ConnectionCore(Role.CLIENT, io.kuicksilver.http2.Http2Settings(), 0)
        val out = ByteArray(1024)
        val n = c.poll(out, 0, 0)
        assertContentEquals(H2.PREFACE, out.copyOf(24)) // section 3.4
        peer.send(out.copyOf(n))
        val s = peer.events()
        assertTrue(H2Event.SettingsChanged in s)
        val settings = assertIs<Frame.Settings>(peer.read().first())
        assertEquals(false, settings.ack) // the server's preface
        // the client's SETTINGS: no push (section 6.5.2) and no RFC 7540 priorities (RFC 9218 section 2.1)
        val decoded =
            io.kuicksilver.http2.frame
                .FrameDecoder()
        decoded.feed(out, 24, n - 24)
        val cs = assertIs<Frame.Settings>(decoded.next())
        val map = cs.ids.indices.associate { cs.ids[it] to cs.values[it] }
        assertEquals(0L, map[SettingId.ENABLE_PUSH])
        assertEquals(1L, map[SettingId.NO_RFC7540_PRIORITIES])
        assertEquals(524_288L, map[SettingId.INITIAL_WINDOW_SIZE])
        decoded.feed(out, 24 + 9 + cs.ids.size * 6, n - 24 - 9 - cs.ids.size * 6)
        assertEquals(786_432 - 65_535, assertIs<Frame.WindowUpdate>(decoded.next()).increment) // the connection window
    }

    @Test
    fun negative_pushPromiseRefused() {
        // before our SETTINGS (ENABLE_PUSH = 0) were acknowledged a push may still come: decoded, then cancelled
        val c = RawH2Peer(Role.CLIENT)
        c.send(FrameEncoder.settings(IntArray(0), LongArray(0)))
        val id = c.core.openStream(GET, true)
        c.read()
        c.send(FrameEncoder.pushPromise(id, 2, c.hpackOut.encode(GET), endHeaders = true))
        c.assertStreamError(2, Http2ErrorCode.CANCEL)
        // after the acknowledgement it is a connection error (section 6.6)
        c.send(FrameEncoder.settingsAck(), FrameEncoder.pushPromise(id, 4, c.hpackOut.encode(GET), endHeaders = true))
        c.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
        // a server never accepts one (section 8.4)
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(
            s.headers(1, endStream = false),
            FrameEncoder.raw(FrameType.PUSH_PROMISE, FrameFlags.END_HEADERS, 1, byteArrayOf(0, 0, 0, 2, 0x82.toByte())),
        )
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }
}
