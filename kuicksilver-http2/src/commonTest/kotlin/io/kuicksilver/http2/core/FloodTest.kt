// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The per-connection flood limits of threat model 3.23, each against the attack it names. */
class FloodTest {
    private fun server(s: Http2Settings = Http2Settings()) = RawH2Peer(Role.SERVER, s).also { it.handshake() }

    @Test
    fun negative_continuationFloodClosesBeforeDecoding() {
        // CVE-2023-45288, CVE-2024-27316: HEADERS without END_HEADERS and CONTINUATION frames that never end
        val s = server()
        s.send(FrameEncoder.headers(1, byteArrayOf(0x82.toByte()), endStream = true, endHeaders = false))
        var sent = 0
        while (sent < 10_000 && !s.core.isClosed) {
            s.send(FrameEncoder.continuation(1, byteArrayOf(0x84.toByte()), false))
            sent++
        }
        assertEquals(9, sent) // the 9th CONTINUATION is one past the limit of 8
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertEquals(emptyList(), s.written.filterIsInstance<Frame.Headers>())
        assertTrue(s.core.blockBufferCapacity <= 65_536)
    }

    @Test
    fun negative_continuationBytesAboveListSize() {
        val s = server(Http2Settings(maxHeaderListSize = 20_000))
        s.send(FrameEncoder.headers(1, ByteArray(16_000), endStream = true, endHeaders = false))
        assertEquals(false, s.core.isClosed)
        s.send(FrameEncoder.continuation(1, ByteArray(4_001), false)) // 20 001 compressed bytes
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertTrue(s.core.blockBufferCapacity <= 20_000) // never buffered past the limit
    }

    @Test
    fun negative_headerBlockTakingTooLongCloses() {
        val s = server()
        s.send(FrameEncoder.headers(1, byteArrayOf(0x82.toByte()), endStream = true, endHeaders = false))
        assertEquals(10 * SECOND, s.core.nextTimeout())
        s.core.onTimeout(10 * SECOND)
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
    }

    @Test
    fun negative_pingFloodBoundedQueue() {
        // CVE-2019-9512: PINGs from a peer that never reads our acknowledgements
        val s = server()
        val ping = FrameEncoder.ping(false, 7)
        val batch = ByteArray(ping.size * 1_000).also { b -> repeat(1_000) { ping.copyInto(b, it * ping.size) } }
        var maxQueued = 0
        repeat(100) {
            if (!s.core.isClosed) s.send(batch)
            maxQueued = maxOf(maxQueued, s.core.controlQueued)
        }
        assertTrue(maxQueued <= 10_000, "queued $maxQueued")
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        // a peer that reads its answers is not punished
        val ok = server()
        repeat(100) {
            ok.send(batch)
            ok.read()
        }
        assertEquals(false, ok.core.isClosed)
    }

    @Test
    fun negative_settingsFloodBounded() {
        // CVE-2019-9515: SETTINGS frames, each owed an acknowledgement
        val s = server()
        val settings = FrameEncoder.settings(intArrayOf(0x3), longArrayOf(100))
        repeat(20_000) { if (!s.core.isClosed) s.send(settings) }
        assertTrue(s.core.controlQueued <= 10_000)
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
    }

    @Test
    fun negative_emptyDataFlood() {
        // CVE-2019-9518: DATA frames with no content and no END_STREAM
        val s = server()
        s.send(s.headers(1, endStream = false))
        repeat(100) { s.send(s.data(1, 0)) }
        assertEquals(false, s.core.isClosed)
        s.send(s.data(1, 0))
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        // content in between resets the count
        val ok = server()
        ok.send(ok.headers(1, endStream = false))
        repeat(10) {
            repeat(100) { ok.send(ok.data(1, 0)) }
            ok.send(ok.data(1, 1))
        }
        assertEquals(false, ok.core.isClosed)
    }

    @Test
    fun negative_rapidResetExhaustsBudget() {
        // CVE-2023-44487: HEADERS + RST_STREAM, 2000 times within one second; the engine ends each handler at its reset
        val s = server()
        var maxRunning = 0
        var opened = 0
        for (i in 0 until 2_000) {
            if (s.core.isClosed) break
            val id = 1 + 2 * i
            s.now = i * 500_000L // 2000 in one second
            s.send(s.headers(id, endStream = true), FrameEncoder.rstStream(id, Http2ErrorCode.CANCEL.code))
            for (e in s.events()) {
                if (e is H2Event.HeadersReceived) opened++
                if (e is H2Event.StreamReset) s.core.release(e.streamId)
            }
            maxRunning = maxOf(maxRunning, s.core.activeStreams)
            s.read()
        }
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertTrue(opened in 1_000..1_020, "streams before GOAWAY: $opened") // the burst of 1000, plus the refill of 33/s
        assertTrue(maxRunning <= 100)
    }

    @Test
    fun negative_rapidResetHandlersStayWithinConcurrency() {
        // the same attack against an engine whose handlers keep running after the reset: they still count (golang/go#63417)
        val s = server()
        var maxRunning = 0
        for (i in 0 until 2_000) {
            if (s.core.isClosed) break
            val id = 1 + 2 * i
            s.send(s.headers(id, endStream = true), FrameEncoder.rstStream(id, Http2ErrorCode.CANCEL.code))
            s.events()
            maxRunning = maxOf(maxRunning, s.core.activeStreams)
            s.read()
        }
        assertEquals(100, maxRunning)
        assertTrue(s.resets().count { it.errorCode == Http2ErrorCode.REFUSED_STREAM.code } in 300..400)
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM) // more than 4 x 100 refused in a row
    }

    @Test
    fun negative_madeYouResetCountsOurResets() {
        // CVE-2025-8671: frames that make *us* reset streams (WINDOW_UPDATE of 0), never a RST_STREAM from the peer
        val s = server()
        for (i in 0 until 2_000) {
            if (s.core.isClosed) break
            val id = 1 + 2 * i
            s.send(s.headers(id, endStream = true), FrameEncoder.windowUpdate(id, 0))
            for (e in s.events()) if (e is H2Event.StreamReset) s.core.release(e.streamId)
            s.read()
        }
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertTrue(s.resets().size in 1_000..1_010, "our resets before GOAWAY: ${s.resets().size}")
    }

    @Test
    fun negative_resetStreamStillRunningCountsTowardConcurrency() {
        val s = server(Http2Settings(maxConcurrentStreams = 2))
        s.send(s.headers(1, endStream = false), s.headers(3, endStream = false))
        s.send(FrameEncoder.rstStream(1, 8), FrameEncoder.rstStream(3, 8)) // reset, but their handlers have not returned
        s.send(s.headers(5, endStream = true))
        s.assertStreamError(5, Http2ErrorCode.REFUSED_STREAM)
        s.core.release(1)
        s.send(s.headers(7, endStream = true))
        assertEquals(listOf(1, 3, 7), s.events().filterIsInstance<H2Event.HeadersReceived>().map { it.streamId })
    }

    @Test
    fun resetBudgetRefills() {
        // a browser that cancels 30 streams a second for a minute is not punished (33 per second refill)
        val s = server()
        var id = 1
        for (sec in 0 until 60) {
            for (k in 0 until 30) {
                s.now = sec * SECOND + k * 30 * MS
                s.send(s.headers(id, endStream = true), FrameEncoder.rstStream(id, Http2ErrorCode.CANCEL.code))
                for (e in s.events()) if (e is H2Event.StreamReset) s.core.release(e.streamId)
                id += 2
            }
            s.read()
        }
        assertEquals(false, s.core.isClosed)
        assertEquals(null, s.goAway())
    }

    @Test
    fun negative_priorityFloodCreatesNoState() {
        // CVE-2019-9513: PRIORITY frames build no tree here (section 5.3.2): no state, no output
        val s = server()
        repeat(50_000) { s.send(FrameEncoder.priority(1 + 2 * it, 1 + 2 * ((it + 1) % 50_000))) }
        assertEquals(0, s.core.activeStreams)
        assertEquals(emptyList(), s.read())
        assertEquals(false, s.core.isClosed)
    }
}
