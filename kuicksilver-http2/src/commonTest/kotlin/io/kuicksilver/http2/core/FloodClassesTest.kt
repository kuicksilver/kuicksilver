// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The flood classes of RFC 9113 section 10.5 and the 2019 HTTP/2 advisories, each against both cores with the attacker
 * never reading what we write (nothing is polled until the flood ends): PING (CVE-2019-9512), SETTINGS (CVE-2019-9515),
 * empty frames (CVE-2019-9518), zero-length field blocks (CVE-2019-9516), resets we are made to send (CVE-2019-9514),
 * PRIORITY shuffling (CVE-2019-9513) and WINDOW_UPDATE floods (CVE-2019-9511, the data dribble). "An endpoint MAY treat
 * activity that is suspicious as a connection error of type ENHANCE_YOUR_CALM" (section 10.5): each flood that makes
 * us answer or hold state ends with GOAWAY ENHANCE_YOUR_CALM, while what the core holds for the peer stays within the
 * measured bound ([Held]); the WINDOW_UPDATE floods make us hold nothing and answer nothing, and end only where the
 * protocol says (FLOW_CONTROL_ERROR above 2^31 - 1).
 */
class FloodClassesTest {
    /** The most the core held at once while a flood went on: control frames and their bytes, streams, queued DATA. */
    private class Held {
        var frames = 0
        var control = 0
        var controlBytes = 0L
        var streams = 0
        var queuedData = 0L

        fun see(core: H2ConnectionCore) {
            control = maxOf(control, core.controlQueued)
            controlBytes = maxOf(controlBytes, core.controlQueuedBytes)
            streams = maxOf(streams, core.activeStreams)
            queuedData = maxOf(queuedData, core.connectionSendWindowAccounted - core.connSendWindow)
        }

        override fun toString() =
            "$frames frames: at most $control control frames ($controlBytes bytes), $streams streams, $queuedData DATA bytes held"
    }

    /** A peer of [role] after the handshake (our SETTINGS acknowledged), with the preface and SETTINGS read. */
    private fun peer(
        role: Role,
        s: Http2Settings = Http2Settings(),
    ) = RawH2Peer(role, s).also {
        it.handshake()
        it.events()
    }

    /** Sends what [frame] makes until the core closes or [max] frames went, without reading anything back. */
    private fun RawH2Peer.flood(
        max: Int,
        onEvents: (List<H2Event>) -> Unit = {},
        frame: (Int) -> ByteArray,
    ): Held {
        val h = Held()
        while (h.frames < max && !core.isClosed) {
            send(frame(h.frames))
            h.frames++
            if (!core.isClosed) h.see(core) // what the core holds for the peer, not the GOAWAY that ends it
            onEvents(events())
        }
        return h
    }

    private fun Held.assertWithin(
        control: Int,
        bytes: Long,
    ) {
        assertTrue(this.control <= control && controlBytes <= bytes, "$this")
    }

    @Test
    fun negative_pingFloodWithoutReading() {
        // CVE-2019-9512: every PING is owed an answer; with nothing of ours written in between each is a glitch too
        for (role in Role.entries) {
            val p = peer(role)
            val h = p.flood(100_000) { FrameEncoder.ping(false, it.toLong()) }
            println("PING flood, $role core: $h")
            p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertTrue(h.frames in 10_000..10_002, "$role: $h")
            h.assertWithin(10_000, 10_000L * 17)
        }
    }

    @Test
    fun negative_pingFloodFillsTheQueueBeforeTheGlitchBudget() {
        // the queue's own bound, where it is the smaller one: the 101st unanswered PING ends the connection
        for (role in Role.entries) {
            val p = peer(role, Http2Settings(maxControlFramesQueued = 100))
            val h = p.flood(100_000) { FrameEncoder.ping(false, it.toLong()) }
            p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertEquals(101, h.frames, "$role")
            assertTrue("control frames queued" in p.goAway()!!.debug.decodeToString(), "$role")
            h.assertWithin(100, 100L * 17)
        }
    }

    @Test
    fun negative_settingsFloodWithoutReading() {
        // CVE-2019-9515: every SETTINGS is owed an ACK; the values change the windows of every stream (the costly kind)
        for (role in Role.entries) {
            val p = peer(role)
            if (role == Role.CLIENT) p.core.openStream(GET, endStream = false) else p.send(p.headers(1, endStream = false))
            val h = p.flood(100_000) { FrameEncoder.settings(intArrayOf(0x4, 0x1), longArrayOf(1L + (it and 1), 4_096L - (it and 1))) }
            println("SETTINGS flood, $role core: $h")
            p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertTrue(h.frames in 10_000..10_002, "$role: $h")
            h.assertWithin(10_000, 10_000L * 9 + 64)
        }
        // with the queue the smaller bound, the queue ends it
        for (role in Role.entries) {
            val p = peer(role, Http2Settings(maxControlFramesQueued = 50))
            val h = p.flood(100_000) { FrameEncoder.settings(IntArray(0), LongArray(0)) }
            p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertEquals(51, h.frames, "$role")
            assertTrue("control frames queued" in p.goAway()!!.debug.decodeToString(), "$role")
        }
    }

    /** A stream the peer may send DATA on: a request (server core) or a response (client core), our side ended. */
    private fun RawH2Peer.openForData(): Int {
        if (core.client) {
            val id = core.openStream(GET, endStream = true)
            read()
            send(headers(id, OK, endStream = false))
            events()
            return id
        }
        send(headers(1, endStream = false))
        events()
        return 1
    }

    @Test
    fun negative_emptyFrameFloodsWithoutReading() {
        // CVE-2019-9518: frames that carry nothing and cost a frame's processing each
        for (role in Role.entries) {
            val data = peer(role)
            val id = data.openForData()
            val h = data.flood(100_000) { data.data(id, 0) }
            println("empty DATA flood, $role core: $h")
            data.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertEquals(101, h.frames, "$role: the 101st in a row")

            // empty CONTINUATION frames after a HEADERS without END_HEADERS
            val cont = peer(role)
            val block = if (role == Role.CLIENT) cont.core.openStream(GET, endStream = true).also { cont.read() } else 1
            cont.send(
                FrameEncoder.headers(
                    block,
                    cont.hpackOut.encode(
                        if (role ==
                            Role.CLIENT
                        ) {
                            OK
                        } else {
                            GET
                        },
                    ),
                    endStream = true,
                    endHeaders = false,
                ),
            )
            val c = cont.flood(100_000) { FrameEncoder.continuation(block, ByteArray(0), endHeaders = false) }
            println("empty CONTINUATION flood, $role core: $c")
            cont.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertEquals(9, c.frames, "$role: the 9th CONTINUATION")

            // empty frames of an unknown type (section 5.5: ignored, each a glitch)
            val unknown = peer(role)
            val u = unknown.flood(100_000) { FrameEncoder.raw(0xfa, 0, 0, ByteArray(0)) }
            unknown.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertTrue(u.frames in 10_000..10_002, "$role: $u")
            assertEquals(0, u.control, "$role: unknown frames are never answered")
        }
    }

    @Test
    fun negative_zeroLengthFieldBlockFloodWithoutReading() {
        // CVE-2019-9516: field blocks that decode to nothing. A request without pseudo-header fields is malformed (section
        // 8.1.1); the engine resets each (H2Runtime.malformed) as an error the peer caused, which takes from the glitch budget
        val p = peer(Role.SERVER)
        val h =
            p.flood(100_000, onEvents = { evs ->
                for (e in evs) {
                    if (e is H2Event.HeadersReceived) {
                        p.core.reset(e.streamId, Http2ErrorCode.PROTOCOL_ERROR, p.now, causedByPeer = true)
                        p.core.release(e.streamId)
                    }
                }
            }) { FrameEncoder.headers(1 + 2 * it, ByteArray(0), endStream = true, endHeaders = true) }
        println("zero-length HEADERS flood, server core: $h")
        p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertTrue(h.frames in 10_000..10_002, "$h")
        h.assertWithin(10_000, 10_000L * 13)
        assertTrue(h.streams <= 1, "$h")
    }

    @Test
    fun negative_resetsWeAreMadeToSendWithoutReading() {
        // CVE-2019-9514: frames that each make us send RST_STREAM. A request that ended, then DATA on it (STREAM_CLOSED,
        // section 5.1): a stream error of the peer's, so a glitch each; one reset per stream, later frames there are ignored
        val p = peer(Role.SERVER)
        val h =
            p.flood(100_000, onEvents = { evs -> for (e in evs) if (e is H2Event.StreamReset) p.core.release(e.streamId) }) {
                p.headers(1 + 2 * it, endStream = true) + p.data(1 + 2 * it, 1)
            }
        println("STREAM_CLOSED reset flood, server core: $h")
        p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertTrue(h.frames in 10_000..10_002, "$h")
        h.assertWithin(10_000, 10_000L * 13)
        assertTrue(h.streams <= 100, "$h") // the handlers of reset streams still count (Rapid Reset)
        val again = peer(Role.SERVER)
        val id = again.openForData()
        again.send(again.data(id, 1, endStream = true))
        val one = again.flood(1_000) { again.data(id, 1) }
        assertEquals(false, again.core.isClosed)
        assertEquals(1, again.read().count { it is io.kuicksilver.http2.frame.Frame.RstStream }, "one reset per stream: $one")
        // requests past SETTINGS_MAX_CONCURRENT_STREAMS, each refused: more than 4 x the limit in a row ends it
        val s = peer(Role.SERVER, Http2Settings(maxConcurrentStreams = 10))
        val refused = s.flood(100_000) { s.headers(1 + 2 * it, endStream = false) }
        println("REFUSED_STREAM flood, server core: $refused")
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertEquals(10 + 41, refused.frames, "10 accepted, 41 refused")
        refused.assertWithin(41, 41L * 13)
    }

    /**
     * RFC 9113 section 5.1.2: "An endpoint that receives a HEADERS frame that causes its advertised concurrent stream limit
     * to be exceeded MUST treat this as a stream error". Once our SETTINGS are acknowledged the peer knows the limit, so
     * each refusal is an error it caused: a glitch. A peer that keeps 300 refused requests per round behind 100 that run,
     * and lets the handlers finish between rounds, never has more than 4 x the limit refused in a row; the glitch budget
     * ends it.
     */
    @Test
    fun negative_refusedStreamsBetweenFinishedRoundsEndCalm() {
        val p = peer(Role.SERVER)
        var next = 1
        var refused = 0
        var rounds = 0
        while (!p.core.isClosed && rounds < 200) {
            val accepted = mutableListOf<Int>()
            repeat(400) {
                if (!p.core.isClosed) p.send(p.headers(next, endStream = true))
                next += 2
            }
            for (e in p.events()) if (e is H2Event.HeadersReceived) accepted += e.streamId
            for (id in accepted) {
                if (p.core.isClosed) break
                p.core.sendHeaders(id, OK, endStream = true)
                p.core.release(id) // the handler finished
            }
            refused +=
                p.read().count { it is io.kuicksilver.http2.frame.Frame.RstStream && it.errorCode == Http2ErrorCode.REFUSED_STREAM.code }
            rounds++
        }
        p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        refused = p.resets().count { it.errorCode == Http2ErrorCode.REFUSED_STREAM.code }
        println("refused streams between finished rounds, server core: $refused refused in $rounds rounds")
        assertTrue(refused in 9_000..10_001, "refused before GOAWAY: $refused")
        // before the peer has our SETTINGS it cannot know the limit: a burst then costs nothing
        val early = RawH2Peer(Role.SERVER, Http2Settings(maxConcurrentStreams = 10, glitchBurst = 5))
        early.send(H2.PREFACE, FrameEncoder.settings(IntArray(0), LongArray(0)))
        for (i in 0 until 20) early.send(early.headers(1 + 2 * i, endStream = true))
        assertEquals(false, early.core.isClosed)
        assertEquals(10, early.read().count { it is io.kuicksilver.http2.frame.Frame.RstStream })
    }

    @Test
    fun negative_priorityShufflingWithoutReading() {
        // CVE-2019-9513: dependencies that change on every frame; no tree is kept (section 5.3.2), each frame is a glitch
        for (role in Role.entries) {
            val p = peer(role)
            val h = p.flood(100_000) { FrameEncoder.priority(1 + 2 * (it % 100), 1 + 2 * ((it * 7 + 3) % 100)) }
            println("PRIORITY shuffling, $role core: $h")
            p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertTrue(h.frames in 10_000..10_002, "$role: $h")
            assertEquals(0, h.control, "$role")
            assertEquals(0, h.streams, "$role")
        }
        // RFC 9218 PRIORITY_UPDATE: the same for a server; a client takes none (section 7.1: PROTOCOL_ERROR)
        val s = peer(Role.SERVER)
        val updates = s.flood(100_000) { FrameEncoder.priorityUpdate(1 + 2 * (it % 50), "u=${it % 8}") }
        s.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
        assertTrue(updates.frames in 10_000..10_002, "$updates")
        assertTrue(s.core.earlyPriority.size <= 100, "values kept for idle streams: ${s.core.earlyPriority.size}")
        val c = peer(Role.CLIENT)
        c.send(FrameEncoder.priorityUpdate(1, "u=1"))
        c.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    /**
     * RFC 9113 section 10.5 lists "Providing tiny increments to flow control in WINDOW_UPDATE frames" and "Large numbers of
     * small or empty frames" among the abuses, and "Implementations SHOULD track the use of these features and set limits
     * on their use". An increment below 1024 bytes on a window we wrote no DATA against since the last such increment is a
     * glitch: a flood of them (here +1 on the connection, and on a stream that has ended) ends with ENHANCE_YOUR_CALM.
     */
    @Test
    fun negative_tinyWindowUpdateFloodEndsCalm() {
        for (role in Role.entries) {
            val p = peer(role)
            val conn = p.flood(100_000) { FrameEncoder.windowUpdate(0, 1) }
            println("WINDOW_UPDATE +1 flood, $role core: $conn")
            p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertTrue(conn.frames in 9_990..10_002, "$role: $conn")
            assertEquals(0, conn.control, "$role: never answered")

            val q = peer(role)
            val id = q.openForData()
            q.send(q.data(id, 0, endStream = true))
            if (role == Role.SERVER) q.core.sendHeaders(id, OK, endStream = true) // the stream is closed both ways
            q.events()
            val closed = q.flood(100_000) { FrameEncoder.windowUpdate(id, 1) }
            q.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            assertTrue(closed.frames in 9_990..10_002, "$role: $closed")
        }
    }

    /**
     * Credit that follows our DATA is what a reader sends, however small: an implementation that credits each DATA frame it
     * read (Jetty's SimpleFlowControlStrategy) gets a stream of 10-byte frames and answers each with 10-byte increments on
     * the stream and the connection, 20 000 times, and is not punished.
     */
    @Test
    fun tinyCreditsAfterOurDataAreFree() {
        val s = peer(Role.SERVER)
        s.send(s.headers(1, endStream = true))
        s.core.sendHeaders(1, OK, endStream = false)
        repeat(20_000) {
            assertEquals(10, s.core.sendData(1, ByteArray(10), 0, 10, endStream = false))
            s.read()
            s.send(FrameEncoder.windowUpdate(0, 10), FrameEncoder.windowUpdate(1, 10))
        }
        assertEquals(false, s.core.isClosed)
    }

    /**
     * Large increments are bounded by the window itself: with nothing of ours written, the connection window passes
     * 2^31 - 1 after at most 2^31 / increment frames and the connection ends with FLOW_CONTROL_ERROR (section 6.9.1); none
     * is answered or builds state. Increments on a finished stream change nothing (Go's client credits a body it still
     * reads after our END_STREAM, 4 KiB at a time, so they are not counted).
     */
    @Test
    fun windowUpdateFloodsHoldNothing() {
        for (role in Role.entries) {
            val p = peer(role)
            val conn = p.flood(100_000) { FrameEncoder.windowUpdate(0, 65_536) }
            println("WINDOW_UPDATE 64 KiB flood, $role core: $conn")
            p.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR)
            assertEquals((H2.MAX_WINDOW - H2.DEFAULT_WINDOW).toInt() / 65_536 + 1, conn.frames, "$role")
            assertEquals(0, conn.control, "$role: $conn")

            val q = peer(role)
            val id = q.openForData()
            q.send(q.data(id, 0, endStream = true))
            if (role == Role.SERVER) q.core.sendHeaders(id, OK, endStream = true)
            q.events()
            val closed = q.flood(100_000) { FrameEncoder.windowUpdate(id, 4_096) }
            assertEquals(false, q.core.isClosed, "$role")
            assertTrue(closed.control <= 1 && closed.streams <= 1, "$role: $closed")
        }
    }

    /**
     * CVE-2019-9511, the data dribble: the peer opens its windows a byte at a time. The core takes at most one frame per
     * stream from the writer ("Inefficient tracking of outstanding outbound frames can lead to overload", section 10.5),
     * so a peer that does not read makes us hold one byte per stream, and its increments, which no DATA of ours follows,
     * end it with ENHANCE_YOUR_CALM. A peer that reads each 1-byte frame before the next increment costs us one frame for
     * each frame it sends, and holds no more.
     */
    @Test
    fun negative_dataDribbleHoldsOneFramePerStream() {
        for (reads in listOf(false, true)) {
            val p = peer(Role.SERVER, Http2Settings(maxConcurrentStreams = 100))
            p.send(FrameEncoder.settings(intArrayOf(0x4), longArrayOf(0)))
            for (i in 0 until 100) {
                p.send(p.headers(1 + 2 * i, endStream = true))
                p.core.sendHeaders(1 + 2 * i, OK, endStream = false)
            }
            p.events()
            p.read()
            val body = ByteArray(1 shl 20)
            val h =
                p.flood(if (reads) 50_000 else 100_000) { i ->
                    val id = 1 + 2 * (i % 100)
                    // the writer is offered its window as soon as it has some: it takes what fits
                    p.core.sendData(id, body, 0, body.size, endStream = false)
                    // time passes for a peer that reads (the core waits up to REFILL_GRACE_NANOS for a woken writer)
                    if (reads) p.now += 3 * MS
                    if (reads) p.read()
                    FrameEncoder.windowUpdate(id, 1)
                }
            println("data dribble (reading: $reads), server core: $h")
            assertTrue(h.queuedData <= 100, "$h")
            assertTrue(h.control <= 1, "$h")
            if (reads) {
                assertEquals(false, p.core.isClosed, "${p.allEvents.filterIsInstance<H2Event.Closed>().map { it.reason }}")
            } else {
                p.assertConnectionError(Http2ErrorCode.ENHANCE_YOUR_CALM)
            }
        }
    }
}
