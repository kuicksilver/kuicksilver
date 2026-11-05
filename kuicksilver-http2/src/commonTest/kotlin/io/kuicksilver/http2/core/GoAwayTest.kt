// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class GoAwayTest {
    @Test
    fun streamsAboveLastIdReportedUnprocessed() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val ids = (1..3).map { c.core.openStream(GET, endStream = true) }
        c.read()
        c.send(FrameEncoder.goAway(1, Http2ErrorCode.NO_ERROR.code, "bye".encodeToByteArray()))
        val ev = c.events()
        val g = ev.only<H2Event.GoAway>()
        assertEquals(1, g.lastStreamId)
        // section 6.8: 3 and 5 were not processed, so the engine may retry them on another connection
        val unprocessed = ev.filterIsInstance<H2Event.StreamReset>()
        assertEquals(listOf(3, 5), unprocessed.map { it.streamId })
        assertTrue(unprocessed.all { it.notProcessed && it.byPeer })
        ids.drop(1).forEach { c.core.release(it) }
        assertFailsWith<H2ConnectionUnusable> { c.core.openStream(GET, endStream = true) } // section 6.8: no new streams
        // stream 1 goes on to its end, then the connection is over
        c.send(c.headers(ids[0], OK, endStream = true))
        c.core.release(ids[0])
        val end = c.events()
        assertEquals(ids[0], end.only<H2Event.HeadersReceived>().streamId)
        assertEquals(Http2ErrorCode.NO_ERROR, end.only<H2Event.Closed>().code)
        // a later GOAWAY cannot raise the last stream identifier
        c.send(FrameEncoder.goAway(5, 0, ByteArray(0)))
        assertEquals(emptyList(), c.events().filterIsInstance<H2Event.GoAway>())
    }

    @Test
    fun unprocessedStreamsAreReportedInTheOrderTheyWereOpened() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        // fifteen streams (1..29) answered and released, so the next ids (31, 33, 35) no longer fall into a hash table's
        // buckets in their numeric order
        repeat(15) {
            val id = c.core.openStream(GET, endStream = true)
            c.send(c.headers(id, OK, endStream = true))
            c.core.release(id)
        }
        val ids = (1..3).map { c.core.openStream(GET, endStream = true) }
        assertEquals(listOf(31, 33, 35), ids)
        c.read()
        c.events()
        c.send(FrameEncoder.goAway(29, Http2ErrorCode.NO_ERROR.code, ByteArray(0)))
        // the engine retries them on another connection in this order, so it is the order the requests were made in
        val unprocessed = c.events().filterIsInstance<H2Event.StreamReset>()
        assertEquals(ids, unprocessed.map { it.streamId })
    }

    /** A second graceful GOAWAY (the engine stops while an idle close is under way) keeps the first one's two steps. */
    @Test
    fun repeatedGracefulGoAwayKeepsTheTwoSteps() {
        val p = RawH2Peer(Role.SERVER)
        p.handshake()
        p.send(p.headers(1, endStream = true))
        p.core.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = true, now = p.now)
        p.core.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = true, now = p.now)
        p.read()
        assertEquals(listOf(H2.MAX_STREAM_ID), p.written.filterIsInstance<Frame.GoAway>().map { it.lastStreamId })
        // a request that crosses the first GOAWAY is still taken
        p.send(p.headers(3, endStream = true))
        val ping = p.written.filterIsInstance<Frame.Ping>().single { !it.ack }
        p.send(
            io.kuicksilver.http2.frame.FrameEncoder
                .ping(true, ping.payload),
        )
        p.read()
        assertEquals(listOf(H2.MAX_STREAM_ID, 3), p.written.filterIsInstance<Frame.GoAway>().map { it.lastStreamId })
    }

    @Test
    fun twoPhaseGoAwayFromServer() {
        val p = H2Pair()
        val first = p.client.openStream(GET, endStream = true)
        p.pump()
        p.server.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = true, now = p.now)
        // the first GOAWAY carries 2^31 - 1 and a PING follows; a request that crosses it is still accepted
        val out = ByteArray(1024)
        val n = p.server.poll(out, 0, p.now)
        val dec =
            io.kuicksilver.http2.frame
                .FrameDecoder()
        var at = 0
        val frames = mutableListOf<Frame>()
        while (at < n) {
            at += dec.feed(out, at, n - at)
            dec.next()?.let { frames += it }
        }
        assertEquals(H2.MAX_STREAM_ID, frames.filterIsInstance<Frame.GoAway>().single().lastStreamId)
        assertTrue(frames.any { it is Frame.Ping && !it.ack })
        // a request on the wire before the client read the GOAWAY
        val crossing = p.client.openStream(GET, endStream = true)
        val wire = ByteArray(1024)
        val m = p.client.poll(wire, 0, p.now)
        p.server.receive(wire, 0, m, p.now)
        // and one still in the client's queue when the GOAWAY and PING arrive: the PING answer goes out first (section
        // 6.7), so the second GOAWAY does not cover it
        val late = p.client.openStream(GET, endStream = true)
        p.client.receive(out, 0, n, p.now)
        p.pump()
        // the client answered the PING: the second GOAWAY names the last stream the server accepted
        assertEquals(listOf(first, crossing), p.serverGot<H2Event.HeadersReceived>().map { it.streamId })
        val goaways = p.clientGot<H2Event.GoAway>()
        assertEquals(listOf(H2.MAX_STREAM_ID, crossing), goaways.map { it.lastStreamId })
        // the late one is reported as not processed (retry-safe), never lost
        val r = p.clientGot<H2Event.StreamReset>().single()
        assertEquals(late, r.streamId)
        assertTrue(r.notProcessed)
        // the server finishes its streams, then the connection closes on both sides
        for (id in listOf(first, crossing)) {
            p.server.sendHeaders(id, OK, endStream = true)
            p.server.release(id)
        }
        p.pump()
        for (id in listOf(first, crossing, late)) p.client.release(id)
        p.pump()
        assertEquals(Http2ErrorCode.NO_ERROR, p.serverGot<H2Event.Closed>().single().code)
        assertEquals(2, p.clientGot<H2Event.HeadersReceived>().size)
        assertTrue(p.client.isClosed)
    }

    @Test
    fun gracefulGoAwayFinishesWithoutAPingAnswer() {
        // the client never answers the PING of a graceful GOAWAY: the final GOAWAY goes out at the deadline anyway
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(s.headers(1, endStream = false))
        s.core.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = true, now = 0)
        assertEquals(listOf(H2.MAX_STREAM_ID), s.read().filterIsInstance<Frame.GoAway>().map { it.lastStreamId })
        repeat(20) { s.core.ping(0) } // our own PINGs do not push the graceful one out
        assertEquals(10 * SECOND, s.core.nextTimeout())
        s.core.onTimeout(10 * SECOND)
        assertEquals(
            1,
            s
                .read()
                .filterIsInstance<Frame.GoAway>()
                .single()
                .lastStreamId,
        )
    }

    @Test
    fun negative_newStreamAfterGoAwayRefused() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(s.headers(1, endStream = false))
        s.core.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = false, now = 0)
        assertEquals(
            1,
            s
                .read()
                .filterIsInstance<Frame.GoAway>()
                .single()
                .lastStreamId,
        )
        s.events()
        // section 6.8: a stream above the last one is discarded, but its field block still feeds HPACK
        s.send(s.headers(3, GET + ("x-new" to "1"), endStream = true))
        assertEquals(emptyList(), s.events().filterIsInstance<H2Event.HeadersReceived>())
        s.send(s.data(1, 1, endStream = true)) // stream 1 still works, and HPACK is in step for later blocks
        assertEquals(1, s.events().only<H2Event.Data>().streamId)
        s.send(s.data(3, 5)) // DATA of the discarded stream: dropped without a reset
        s.read()
        assertEquals(emptyList(), s.resets())
        // an error GOAWAY after the graceful one does not raise the last stream identifier (section 6.8)
        s.core.goAway(Http2ErrorCode.INTERNAL_ERROR, ByteArray(0), graceful = false, now = 0)
        assertEquals(listOf(1, 1), s.read().let { s.written.filterIsInstance<Frame.GoAway>().map { it.lastStreamId } })
        // a client that sent GOAWAY itself opens nothing more
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        c.core.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = false, now = 0)
        assertFailsWith<H2ConnectionUnusable> { c.core.openStream(GET, endStream = true) }
    }

    @Test
    fun goAwayWithAnErrorClosesAtOnce() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = false)
        c.core.sendData(id, ByteArray(10), 0, 10, endStream = false)
        c.core.goAway(Http2ErrorCode.INTERNAL_ERROR, "oops".encodeToByteArray(), graceful = false, now = 0)
        val out = c.read()
        assertEquals(Http2ErrorCode.INTERNAL_ERROR.code, out.filterIsInstance<Frame.GoAway>().single().errorCode)
        val ev = c.events()
        assertEquals(id, ev.only<H2Event.StreamReset>().streamId)
        assertEquals(Http2ErrorCode.INTERNAL_ERROR, ev.only<H2Event.Closed>().code)
    }
}
