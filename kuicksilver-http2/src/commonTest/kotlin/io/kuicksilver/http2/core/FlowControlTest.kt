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
import kotlin.test.assertTrue

class FlowControlTest {
    private fun settings(vararg kv: Pair<Int, Long>) =
        FrameEncoder.settings(kv.map { it.first }.toIntArray(), kv.map { it.second }.toLongArray())

    /** A client core whose server (the raw peer) answered stream 1 with headers. */
    private fun clientWithResponse(s: Http2Settings = Http2Settings()): Pair<RawH2Peer, Int> {
        val c = RawH2Peer(Role.CLIENT, s)
        c.handshake()
        val id = c.core.openStream(GET, endStream = true)
        c.read()
        c.send(c.headers(id, OK, endStream = false))
        c.events()
        return c to id
    }

    @Test
    fun windowUpdateOnlyAfterConsumed() {
        val (c, id) = clientWithResponse()
        // the server fills the whole 512 KiB stream window; nothing is read by the application
        repeat(32) { c.send(c.data(id, 16_384)) }
        assertEquals(32, c.events().filterIsInstance<H2Event.Data>().size)
        assertEquals(emptyList(), c.read().filterIsInstance<Frame.WindowUpdate>())
        // one byte more is beyond the window: the sender had to stop (section 6.9.1)
        c.send(c.data(id, 1))
        c.assertStreamError(id, Http2ErrorCode.FLOW_CONTROL_ERROR)
        // with the application reading, credit comes back
        val (c2, id2) = clientWithResponse()
        repeat(32) { c2.send(c2.data(id2, 16_384)) }
        c2.core.consumed(id2, 200_000, 1 * MS)
        val updates = c2.read().filterIsInstance<Frame.WindowUpdate>()
        assertTrue(updates.any { it.streamId == id2 } && updates.any { it.streamId == 0 })
    }

    @Test
    fun senderStopsAtTheWindowUntilTheReceiverReads() {
        val p = H2Pair()
        val id = p.client.openStream(GET, endStream = true)
        p.pump()
        p.server.sendHeaders(id, OK, endStream = false)
        val chunk = ByteArray(16_384)
        var sent = 0L
        while (true) {
            val n = p.server.sendData(id, chunk, 0, chunk.size, endStream = false)
            if (n == 0) {
                p.pump()
                if (p.server.sendData(id, chunk, 0, chunk.size, endStream = false).also { sent += it } == 0) break
            } else {
                sent += n
            }
        }
        assertEquals(524_288L, sent) // exactly the client's stream window
        p.client.consumed(id, sent, 1 * MS)
        p.pump()
        assertTrue(p.serverGot<H2Event.WindowAvailable>().any { it.streamId == id })
        assertTrue(p.server.sendData(id, chunk, 0, chunk.size, endStream = false) > 0)
    }

    @Test
    fun autotuneDoublesUpToMax() {
        val c = RawH2Peer(Role.CLIENT)
        c.send(settings())
        c.now = 50 * MS
        c.send(FrameEncoder.settingsAck()) // the acknowledgement of our SETTINGS gives the RTT: 50 ms
        val id = c.core.openStream(GET, endStream = true)
        c.read()
        c.send(c.headers(id, OK, endStream = false))
        var credit = 524_288L // what the server may still send
        var maxCredit = credit
        var sent = 0L
        // the application reads each frame at once, far faster than 4 RTT per window: the window doubles to its maximum
        while (sent < 64L * 1024 * 1024) {
            val n = minOf(16_384L, credit).toInt()
            assertTrue(n > 0, "the sender is stalled at $sent bytes")
            c.send(c.data(id, n))
            sent += n
            credit -= n
            c.now += 10_000
            c.core.consumed(id, n.toLong(), c.now)
            for (u in c.read().filterIsInstance<Frame.WindowUpdate>()) if (u.streamId == id) credit += u.increment
            maxCredit = maxOf(maxCredit, credit)
            c.events()
        }
        assertEquals(6_291_456L, maxCredit) // grew to maxStreamWindow and not beyond
    }

    @Test
    fun negative_dataBeyondWindowIsFlowControlError() {
        // a stream window of 1000 bytes, in force once acknowledged
        val (c, id) = clientWithResponse(Http2Settings(initialStreamWindow = 1_000))
        c.send(c.data(id, 1_001))
        c.assertStreamError(id, Http2ErrorCode.FLOW_CONTROL_ERROR)
        // the connection window: 65 535 + nothing more
        val s =
            RawH2Peer(
                Role.SERVER,
                Http2Settings(initialConnectionWindow = 65_535, initialStreamWindow = 1_000_000, maxStreamWindow = 1_000_000),
            )
        s.handshake()
        s.send(s.headers(1, endStream = false), s.headers(3, endStream = false))
        repeat(3) { s.send(s.data(1, 16_384)) }
        s.send(s.data(3, 16_384)) // 65 536 in total
        s.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR)
    }

    @Test
    fun negative_windowOverflowIsFlowControlError() {
        val (c, id) = clientWithResponse()
        c.send(FrameEncoder.windowUpdate(id, Int.MAX_VALUE)) // 65 535 + 2^31 - 1
        c.assertStreamError(id, Http2ErrorCode.FLOW_CONTROL_ERROR)
        c.send(FrameEncoder.windowUpdate(0, Int.MAX_VALUE))
        c.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR) // section 6.9.1
        // SETTINGS_INITIAL_WINDOW_SIZE that pushes an open stream's window past the maximum (section 6.9.2)
        // (only streams we can still send on have a window that moves: an open one here)
        val c2 = RawH2Peer(Role.CLIENT)
        c2.handshake()
        val id2 = c2.core.openStream(GET, endStream = false)
        c2.read()
        c2.send(FrameEncoder.windowUpdate(id2, Int.MAX_VALUE - 65_535))
        c2.send(settings(SettingId.INITIAL_WINDOW_SIZE to 65_536))
        c2.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR)
    }

    @Test
    fun negative_windowUpdateOfZero() {
        val (c, id) = clientWithResponse()
        c.send(FrameEncoder.windowUpdate(id, 0))
        c.assertStreamError(id, Http2ErrorCode.PROTOCOL_ERROR) // section 6.9
        c.send(FrameEncoder.windowUpdate(0, 0))
        c.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun initialWindowChangeAdjustsOpenStreams() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.INITIAL_WINDOW_SIZE to 100))
        val id = c.core.openStream(GET, endStream = false)
        assertEquals(50, c.core.sendData(id, ByteArray(50), 0, 50, endStream = false))
        c.read()
        // section 6.9.2: 100 -> 10 moves the window by -90: 50 - 90 = -40, below zero
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 10))
        assertEquals(0, c.core.sendData(id, ByteArray(50), 0, 50, endStream = false))
        c.send(FrameEncoder.windowUpdate(id, 45)) // -40 + 45 = 5
        assertTrue(c.events().any { it is H2Event.WindowAvailable && it.streamId == id })
        assertEquals(5, c.core.sendData(id, ByteArray(50), 0, 50, endStream = false))
        c.read()
        // raising it again opens every stream (and a new stream starts with the new value)
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 1_000))
        assertEquals(50, c.core.sendData(id, ByteArray(50), 0, 50, endStream = false))
    }

    @Test
    fun initialWindowChangeLeavesStreamsWeCannotSendOn() {
        // section 6.9.2: only streams with an active send window (open, half-closed (remote)) move
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = true) // half-closed (local): we send nothing more on it
        c.read()
        c.send(FrameEncoder.windowUpdate(id, Int.MAX_VALUE - 65_535))
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 65_536))
        assertEquals(false, c.core.isClosed)
    }

    @Test
    fun aPeerResetPurgesQueuedStreamCreditAndReturnsUnreadContent() {
        val (c, id) = clientWithResponse()
        repeat(32) { c.send(c.data(id, 16_384)) } // 512 KiB delivered
        c.core.consumed(id, 130_000, 1 * MS) // stream credit is due (a quarter of the window) but not written
        c.send(FrameEncoder.rstStream(id, Http2ErrorCode.CANCEL.code))
        val out = c.read()
        assertEquals(emptyList(), out.filterIsInstance<Frame.WindowUpdate>().filter { it.streamId == id }) // section 6.4
        // the connection got back everything delivered, the unread part included
        // (at least all 512 KiB come back; auto-tuning may add more)
        assertTrue(out.filterIsInstance<Frame.WindowUpdate>().filter { it.streamId == 0 }.sumOf { it.increment.toLong() } >= 524_288L)
    }

    @Test
    fun releaseReturnsUnreadContentToTheConnection() {
        val (c, id) = clientWithResponse()
        repeat(16) { c.send(c.data(id, 16_384, endStream = it == 15)) }
        assertEquals(emptyList(), c.read().filterIsInstance<Frame.WindowUpdate>())
        c.core.release(id) // the application dropped the response unread
        assertEquals(262_144L, c.read().filterIsInstance<Frame.WindowUpdate>().sumOf { it.increment.toLong() })
        c.core.consumed(id, 100_000, 2 * MS) // a late report changes nothing
        assertEquals(emptyList(), c.read())
    }

    @Test
    fun zeroWindowSenderBlocksWithoutBuffering() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.INITIAL_WINDOW_SIZE to 0))
        val id = c.core.openStream(GET, endStream = false)
        val big = ByteArray(1_000_000)
        assertEquals(0, c.core.sendData(id, big, 0, big.size, endStream = true))
        val out = c.read()
        assertEquals(1, out.filterIsInstance<Frame.Headers>().size)
        assertEquals(emptyList(), out.filterIsInstance<Frame.Data>()) // nothing queued beyond the field block
        assertTrue(!c.core.wantsWrite)
        // an empty DATA with END_STREAM needs no window
        assertEquals(0, c.core.sendData(id, big, 0, 0, endStream = true))
        assertEquals(1, c.read().filterIsInstance<Frame.Data>().size)
    }

    @Test
    fun oneFrameAtATimePerStream() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = false)
        val big = ByteArray(100_000)
        assertEquals(16_384, c.core.sendData(id, big, 0, big.size, endStream = false)) // one frame
        assertEquals(0, c.core.sendData(id, big, 0, big.size, endStream = false)) // until it is written
        c.read()
        assertTrue(c.events().any { it is H2Event.WindowAvailable })
        assertEquals(16_384, c.core.sendData(id, big, 0, big.size, endStream = false))
    }

    @Test
    fun paddingIsCreditedBackAtOnce() {
        val (c, id) = clientWithResponse(Http2Settings(initialStreamWindow = 65_535, maxStreamWindow = 65_535))
        // 100 frames of 1 byte content and 254 bytes of padding: 25 600 bytes of window, only 100 for the application
        repeat(100) { c.send(FrameEncoder.data(id, byteArrayOf(1), 0, 1, false, padLength = 254)) }
        val updates = c.read().filterIsInstance<Frame.WindowUpdate>()
        assertTrue(updates.sumOf { it.increment.toLong() } > 0) // the padding came back without the application reading
        assertEquals(100, c.events().filterIsInstance<H2Event.Data>().sumOf { it.data.size })
    }
}
