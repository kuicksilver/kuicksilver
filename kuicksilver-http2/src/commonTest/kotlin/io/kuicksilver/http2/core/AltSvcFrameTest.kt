// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.FrameType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The ALTSVC frame (RFC 7838 section 4): "The ALTSVC frame type is 0xa", its payload `Origin-Len (16)`, `Origin?`,
 * `Alt-Svc-Field-Value`. A server sends it ([H2ConnectionCore.sendAltSvc]); a client reports it ([H2Event.AltSvc]) under the
 * section's rules, and a server ignores it.
 */
class AltSvcFrameTest {
    private fun altSvc(
        streamId: Int,
        origin: String,
        value: String,
    ): ByteArray {
        val o = origin.encodeToByteArray()
        val v = value.encodeToByteArray()
        val payload = ByteArray(2 + o.size + v.size)
        payload[0] = (o.size ushr 8).toByte()
        payload[1] = o.size.toByte()
        o.copyInto(payload, 2)
        v.copyInto(payload, 2 + o.size)
        return FrameEncoder.raw(FrameType.ALTSVC, 0, streamId, payload)
    }

    /**
     * "When using HTTP/2 ([RFC7540]), servers SHOULD instead send an ALTSVC frame" (section 3): one on the request's stream,
     * with an empty Origin (the stream's origin), goes out before the response's HEADERS, and the client reports it.
     */
    @Test fun serverSendsAltSvcOnTheStreamBeforeItsResponse() {
        val p = H2Pair()
        val id = p.client.openStream(GET, endStream = true)
        p.pump()
        p.server.sendAltSvc(id, "h3=\":443\"; ma=86400")
        p.server.sendHeaders(id, OK, endStream = true)
        p.pump()
        val a = p.clientEvents.filterIsInstance<H2Event.AltSvc>().single()
        assertEquals(id, a.streamId)
        assertEquals(null, a.origin)
        assertEquals("h3=\":443\"; ma=86400", a.value)
        val order = p.clientEvents.filter { it is H2Event.AltSvc || (it is H2Event.HeadersReceived && it.streamId == id) }
        assertIs<H2Event.AltSvc>(order.first(), "the frame comes before the response")
    }

    /** The raw frame on the wire: type 0xa, no flags, the stream's ID, Origin-Len 0 and the value. */
    @Test fun serverAltSvcFrameLayout() {
        val c = RawH2Peer(Role.SERVER)
        c.handshake()
        c.send(c.headers(1, GET, endStream = true))
        c.events()
        c.core.sendAltSvc(1, "clear")
        val f = c.read().filterIsInstance<Frame.AltSvc>().single()
        assertEquals(1, f.streamId)
        assertEquals("", f.origin)
        assertEquals("clear", f.value)
    }

    /** A server sends it only on a stream it can still send on, and only a value that fits one frame. */
    @Test fun negative_serverAltSvcNeedsAnOpenStreamAndAFittingValue() {
        val c = RawH2Peer(Role.SERVER)
        c.handshake()
        assertFailsWith<IllegalStateException> { c.core.sendAltSvc(1, "clear") }
        c.send(c.headers(1, GET, endStream = true))
        c.events()
        assertFailsWith<IllegalArgumentException> { c.core.sendAltSvc(1, "h3=\":443\"; x=" + "a".repeat(20_000)) }
        c.core.sendHeaders(1, OK, endStream = true)
        assertFailsWith<IllegalStateException> { c.core.sendAltSvc(1, "clear") }
        val client = RawH2Peer(Role.CLIENT)
        client.handshake()
        assertFailsWith<IllegalStateException> { client.core.sendAltSvc(1, "clear") }
    }

    /**
     * Section 4: "An ALTSVC frame from a server to a client on stream 0 indicates that the conveyed alternative service is
     * associated with the origin contained in the Origin field of the frame"; "An ALTSVC frame on stream 0 with empty
     * (length 0) "Origin" information is invalid and MUST be ignored. An ALTSVC frame on a stream other than stream 0
     * containing non-empty "Origin" information is invalid and MUST be ignored." A frame on a stream the client never
     * opened has no origin and is ignored too; a malformed one (Origin-Len past the payload) as well. None is an error.
     */
    @Test fun negative_clientIgnoresInvalidAltSvcFrames() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = false)
        c.read()
        c.send(
            altSvc(0, "", "h3=\":1\""),
            altSvc(id, "https://example.com", "h3=\":2\""),
            altSvc(id + 2, "", "h3=\":3\""),
            altSvc(2, "", "h3=\":4\""),
            FrameEncoder.raw(FrameType.ALTSVC, 0, 0, byteArrayOf(0, 9, 'a'.code.toByte())),
            FrameEncoder.raw(FrameType.ALTSVC, 0, 0, byteArrayOf(0)),
            altSvc(0, "https://example.com", "h3=\":5\""),
            altSvc(id, "", "h3=\":6\""),
        )
        val got = c.events().filterIsInstance<H2Event.AltSvc>()
        assertEquals(
            listOf(Triple(0, "https://example.com", "h3=\":5\""), Triple(id, null, "h3=\":6\"")),
            got.map {
                Triple(it.streamId, it.origin, it.value)
            },
        )
        assertFalse(c.core.isClosed)
    }

    /** "The ALTSVC frame is intended for receipt by clients. A device acting as a server MUST ignore it." */
    @Test fun negative_serverIgnoresAltSvcFrames() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(s.headers(1, GET, endStream = false), altSvc(0, "https://example.com", "h3=\":443\""), altSvc(1, "", "h3=\":443\""))
        val ev = s.events()
        assertTrue(ev.none { it is H2Event.AltSvc }, "$ev")
        assertFalse(s.core.isClosed)
    }
}
