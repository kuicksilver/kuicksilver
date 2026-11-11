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
import kotlin.test.assertIs
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

    /**
     * A streamed body that used the peer's window up exactly still ends: its END_STREAM goes in an empty DATA frame, which
     * needs no window (section 6.9.1), once the last DATA frame was written. Without it the client waits for window the
     * server never grants (it has the whole body) and the server waits for an END_STREAM that never comes.
     */
    @Test
    fun endStreamNeedsNoWindow() {
        val p = H2Pair(serverSettings = Http2Settings(initialStreamWindow = 16_384, maxStreamWindow = 16_384))
        p.pump()
        val id = p.client.openStream(GET.map { if (it.first == ":method") ":method" to "POST" else it }, endStream = false)
        p.pump()
        val chunk = ByteArray(16_384)
        assertEquals(16_384, p.client.sendData(id, chunk, 0, chunk.size, endStream = false))
        // the frame is still queued: one DATA frame at a time
        assertEquals(false, p.client.endStream(id))
        p.pump()
        assertTrue(p.client.endStream(id))
        p.pump()
        val data = p.serverGot<H2Event.Data>()
        assertEquals(16_384, data.sumOf { it.data.size })
        assertTrue(data.last().endStream, "the server sees the end of the body")
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

    /**
     * A client starts its request body under the protocol's initial 65 535 before the server's SETTINGS with a smaller
     * SETTINGS_INITIAL_WINDOW_SIZE arrive (section 3.4). A DATA frame [H2ConnectionCore.sendData] took from the old window but
     * [H2ConnectionCore.poll] had not written yet must reach the server before the SETTINGS acknowledgement: the server
     * counts what follows the acknowledgement against the smaller window (sections 6.5.3, 6.9.2). Written after it, the
     * frame overran that window and the server reset the stream with FLOW_CONTROL_ERROR.
     */
    @Test
    fun dataTakenBeforeASmallerInitialWindowIsWrittenBeforeTheAck() {
        val server = H2ConnectionCore(Role.SERVER, Http2Settings(initialStreamWindow = 16_384, maxStreamWindow = 16_384), 0)
        val client = H2ConnectionCore(Role.CLIENT, Http2Settings(), 0)
        val buf = ByteArray(1 shl 20)
        val serverEvents = mutableListOf<H2Event>()

        fun drain(
            from: H2ConnectionCore,
            to: H2ConnectionCore,
        ) {
            while (true) {
                val n = from.poll(buf, 0, 0)
                if (n == 0) break
                to.receive(buf, 0, n, 0)
            }
            generateSequence { server.nextEvent() }.forEach { serverEvents += it }
            generateSequence { client.nextEvent() }.forEach { }
        }
        val post = GET.map { if (it.first == ":method") ":method" to "POST" else it }
        val id = client.openStream(post, endStream = false)
        val chunk = ByteArray(16_384)
        assertEquals(16_384, client.sendData(id, chunk, 0, chunk.size, endStream = false))
        drain(client, server) // preface, SETTINGS, HEADERS and the first 16 KiB, all under the initial 65 535
        // the server's SETTINGS (initial window 16 384) are on their way; meanwhile the client takes 16 KiB more of the
        // old window, and the read side applies the SETTINGS before the write side wrote that frame
        val serverHello = ByteArray(1 shl 16)
        var helloLen = 0
        while (true) {
            val n = server.poll(serverHello, helloLen, 0)
            if (n == 0) break
            helloLen += n
        }
        assertEquals(16_384, client.sendData(id, chunk, 0, chunk.size, endStream = false))
        client.receive(serverHello, 0, helloLen, 0) // window: 65 535 - 32 768 - 49 151 = -16 384
        drain(client, server)
        assertEquals(emptyList(), serverEvents.filterIsInstance<H2Event.StreamReset>(), "no FLOW_CONTROL_ERROR")
        assertEquals(32_768, serverEvents.filterIsInstance<H2Event.Data>().sumOf { it.data.size })
        // the rest of a 256 KiB body flows within the smaller window as the server reads
        var sent = 32_768
        var rounds = 0
        while (sent < 262_144) {
            assertTrue(++rounds < 1_000, "stalled at $sent")
            server.consumed(id, serverEvents.filterIsInstance<H2Event.Data>().sumOf { it.data.size.toLong() }, 0)
            serverEvents.clear()
            drain(server, client)
            sent += client.sendData(id, chunk, 0, minOf(chunk.size, 262_144 - sent), endStream = sent + chunk.size >= 262_144)
            drain(client, server)
            assertEquals(emptyList(), serverEvents.filterIsInstance<H2Event.StreamReset>(), "no FLOW_CONTROL_ERROR at $sent")
        }
    }

    /** The frame order of [dataTakenBeforeASmallerInitialWindowIsWrittenBeforeTheAck]; a later ACK waits behind a held one. */
    @Test
    fun settingsAckFollowsDataTakenFromTheLargerWindow() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = false)
        assertEquals(16_384, c.core.sendData(id, ByteArray(16_384), 0, 16_384, endStream = false))
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 1_000)) // shrinks: its ACK waits for the queued DATA
        c.send(settings(SettingId.MAX_CONCURRENT_STREAMS to 10)) // its ACK must not overtake the first
        val out = c.read().filter { it is Frame.Data || it is Frame.Settings }
        assertEquals(3, out.size, "wrote ${out.map { it::class.simpleName }}")
        assertTrue(out[0] is Frame.Data)
        assertTrue(out.drop(1).all { it is Frame.Settings && it.ack })
        // without DATA queued, or when the window grows, the ACK goes at once
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 500))
        assertTrue(c.read().any { it is Frame.Settings && it.ack })
        assertEquals(0, c.core.sendData(id, ByteArray(10), 0, 10, endStream = false)) // 1 000 - 16 384 - 500 < 0
        c.send(FrameEncoder.windowUpdate(id, 20_000))
        c.events()
        assertEquals(10, c.core.sendData(id, ByteArray(10), 0, 10, endStream = false))
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 600))
        val grown = c.read()
        assertTrue(grown.first() is Frame.Settings && (grown.first() as Frame.Settings).ack, "wrote ${grown.map { it::class.simpleName }}")
    }

    /** A body's last DATA frame (END_STREAM: the stream is half-closed (local)) still holds the ACK behind it. */
    @Test
    fun lastDataOfAHalfClosedStreamHoldsTheAck() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = false)
        c.read() // HEADERS
        assertEquals(100, c.core.sendData(id, ByteArray(100), 0, 100, endStream = true))
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 10))
        val out = c.read().filter { it is Frame.Data || it is Frame.Settings }
        assertEquals(2, out.size, "wrote ${out.map { it::class.simpleName }}")
        assertTrue(out[0] is Frame.Data && (out[0] as Frame.Data).endStream)
        assertTrue(out[1] is Frame.Settings && (out[1] as Frame.Settings).ack)
    }

    /** Two shrinking SETTINGS in a row, with DATA of other streams taken in between: the ACKs keep their order. */
    @Test
    fun twoShrinkingSettingsKeepTheirAckOrder() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val a = c.core.openStream(GET, endStream = false)
        val b = c.core.openStream(GET, endStream = false)
        c.read() // both HEADERS
        assertEquals(1_000, c.core.sendData(a, ByteArray(1_000), 0, 1_000, endStream = false))
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 30_000)) // first ACK behind a's DATA
        assertEquals(1_000, c.core.sendData(b, ByteArray(1_000), 0, 1_000, endStream = false))
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 20_000)) // second ACK behind the first, and b's DATA
        assertEquals(2, c.core.controlQueued) // both held, and counted toward the control-frame bound
        val out = c.read().filter { it is Frame.Data || it is Frame.Settings }
        assertEquals(4, out.size, "wrote ${out.map { it::class.simpleName }}")
        // each ACK goes as soon as the DATA it waits for is written, the first one before b's DATA
        assertEquals(a, assertIs<Frame.Data>(out[0]).streamId)
        assertTrue(assertIs<Frame.Settings>(out[1]).ack)
        assertEquals(b, assertIs<Frame.Data>(out[2]).streamId)
        assertTrue(assertIs<Frame.Settings>(out[3]).ack)
        assertEquals(0, c.core.controlQueued)
    }

    /** A queued DATA frame that is dropped (the peer reset its stream) releases the ACK held behind it. */
    @Test
    fun droppedDataReleasesTheHeldSettingsAck() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake()
        val id = c.core.openStream(GET, endStream = false)
        c.read() // HEADERS
        assertEquals(16_384, c.core.sendData(id, ByteArray(16_384), 0, 16_384, endStream = false))
        c.send(settings(SettingId.INITIAL_WINDOW_SIZE to 1_000), FrameEncoder.rstStream(id, Http2ErrorCode.CANCEL.code))
        val out = c.read()
        assertEquals(emptyList(), out.filterIsInstance<Frame.Data>())
        assertTrue(out.any { it is Frame.Settings && it.ack })
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
    fun negative_droppedDataReturnsConnectionWindow() {
        // DATA we queued but never wrote (the client cancelled) gives its connection window back: 48 cancelled 16 KiB
        // responses must not exhaust a 768 KiB connection window
        val s = RawH2Peer(Role.SERVER)
        s.handshake(
            settings(SettingId.INITIAL_WINDOW_SIZE to 1_000_000) + FrameEncoder.windowUpdate(0, 786_432 - 65_535),
        )
        val chunk = ByteArray(16_384)
        for (i in 0 until 60) {
            val id = 1 + 2 * i
            s.send(s.headers(id, endStream = true))
            s.core.sendHeaders(id, OK, endStream = false)
            assertEquals(16_384, s.core.sendData(id, chunk, 0, chunk.size, endStream = true), "response $i")
            s.send(FrameEncoder.rstStream(id, Http2ErrorCode.CANCEL.code)) // before anything was written
            s.events()
            s.core.release(id)
        }
        s.read()
        // also when the stream was ended by us (half-closed both ways) and the reset arrives while the DATA waits
        s.send(s.headers(201, endStream = true))
        s.core.sendHeaders(201, OK, endStream = false)
        assertEquals(16_384, s.core.sendData(201, chunk, 0, chunk.size, endStream = true))
        s.send(FrameEncoder.rstStream(201, Http2ErrorCode.CANCEL.code))
        assertEquals(emptyList(), s.read().filterIsInstance<Frame.Data>())
        s.send(s.headers(203, endStream = true))
        s.core.sendHeaders(203, OK, endStream = false)
        assertEquals(16_384, s.core.sendData(203, chunk, 0, chunk.size, endStream = true))
        assertEquals(786_432L, s.core.connectionSendWindowAccounted)
    }

    @Test
    fun negative_clientDroppedRequestDataReturnsConnectionWindow() {
        // reset() of a request whose HEADERS and DATA were never written: the queued DATA gives its window back
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.INITIAL_WINDOW_SIZE to 1_000_000))
        val body = ByteArray(16_384)
        val a = c.core.openStream(GET, endStream = false)
        assertEquals(16_384, c.core.sendData(a, body, 0, body.size, endStream = true))
        c.core.reset(a, Http2ErrorCode.CANCEL, 0)
        assertEquals(65_535L, c.core.connectionSendWindowAccounted)
        assertEquals(emptyList(), c.read().filterIsInstance<Frame.Data>())
        // the peer's GOAWAY drops a request above its last stream while its DATA waits
        val b = c.core.openStream(GET, endStream = false)
        val d = c.core.openStream(GET, endStream = false)
        c.read() // both HEADERS written
        assertEquals(16_384, c.core.sendData(d, body, 0, body.size, endStream = true))
        c.send(FrameEncoder.goAway(b, Http2ErrorCode.NO_ERROR.code, ByteArray(0)))
        assertEquals(65_535L, c.core.connectionSendWindowAccounted)
        assertEquals(emptyList(), c.read().filterIsInstance<Frame.Data>())
        // and stream b can use the whole connection window again
        assertEquals(16_384, c.core.sendData(b, body, 0, body.size, endStream = false))
    }

    @Test
    fun windowUpdatesOnClosedStreamsAreFree() {
        // Go's client sends a WINDOW_UPDATE per 4 KiB it reads, also while it still reads a body whose stream is already closed on our side (transport.go:2261-2265):
        // thousands a second on closed streams on a busy connection, which must not be counted as glitches
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        for (i in 0 until 100) {
            val id = 1 + 2 * i
            s.now = i * 10 * MS // 100 responses in one second
            s.send(s.headers(id, endStream = true))
            s.core.sendHeaders(id, OK, endStream = true)
            s.read()
            s.core.release(id)
            repeat(250) { s.send(FrameEncoder.windowUpdate(id, 4_096)) } // 25 000 in that second
        }
        assertEquals(false, s.core.isClosed)
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
