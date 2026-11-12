// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.FrameType
import io.kuicksilver.http2.frame.SettingId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The order in which a server's responses share the connection (RFC 9218 section 10): urgency first, non-incremental
 * responses of one urgency in ascending stream order, incremental ones sharing, the two kinds taking turns, and a tunnel
 * getting some of the bandwidth whatever its urgency (section 10.1). Each response's writer offers its next frame as soon
 * as the core takes it, as [io.kuicksilver.http2.runtime.H2Runtime]'s body pump does.
 */
class PriorityTest {
    private val frame = 16_384
    private val body = 4 * frame

    /** A server core with windows large enough that only the scheduler decides, and the requests [ids] open. */
    private fun server(vararg requests: Pair<Int, List<Pair<String, String>>>): RawH2Peer {
        val peer = RawH2Peer(Role.SERVER)
        peer.handshake(FrameEncoder.settings(intArrayOf(SettingId.INITIAL_WINDOW_SIZE), longArrayOf(1L shl 24)))
        peer.send(FrameEncoder.windowUpdate(0, (1 shl 24) - 65_535))
        for ((id, fields) in requests) peer.send(peer.headers(id, fields, endStream = fields[0].second != "CONNECT"))
        peer.events()
        for ((id, _) in requests) peer.core.sendHeaders(id, OK, endStream = false)
        return peer
    }

    /**
     * Sends [bodies] (stream to size) the way the runtime does: each writer hands over what it has and offers the rest
     * when the core reports window for it, unless [refills] says no. Returns the stream of every DATA frame written.
     */
    private fun RawH2Peer.drain(
        bodies: Map<Int, Int>,
        refills: (Int) -> Boolean = { true },
    ): List<Int> {
        val left = bodies.toMutableMap()

        fun offer(id: Int) {
            val n = left.getValue(id)
            if (n == 0) return
            left[id] = n - core.sendData(id, ByteArray(n), 0, n, endStream = true)
        }
        bodies.keys.forEach { offer(it) }
        val order = ArrayList<Int>()
        while (true) {
            read().filterIsInstance<Frame.Data>().filter { it.data.isNotEmpty() }.forEach { order += it.streamId }
            val wake = events().filterIsInstance<H2Event.WindowAvailable>().map { it.streamId }.filter(refills)
            if (wake.isEmpty()) {
                // nothing to refill: a writer that did not answer holds the others back only until its grace ends
                val t = core.nextTimeout() ?: break
                if (t <= now) break
                now = t
                core.onTimeout(now)
                continue
            }
            wake.forEach { offer(it) }
        }
        return order
    }

    private fun get(priority: String? = null) = if (priority == null) GET else GET + ("priority" to priority)

    @Test
    fun urgencyFirst() {
        val peer = server(1 to get(), 3 to get())
        peer.core.setPriority(1, urgency = 7, incremental = false)
        peer.core.setPriority(3, urgency = 0, incremental = false)
        assertEquals(List(4) { 3 } + List(4) { 1 }, peer.drain(mapOf(1 to body, 3 to body)))
    }

    /** "Non-incremental responses of the same urgency SHOULD be served [...] in ascending order of the stream ID". */
    @Test
    fun nonIncrementalInStreamOrder() {
        val peer = server(1 to get(), 3 to get())
        assertEquals(List(4) { 1 } + List(4) { 3 }, peer.drain(mapOf(3 to body, 1 to body)))
    }

    /** "Incremental responses of the same urgency SHOULD be served by sharing bandwidth among them." */
    @Test
    fun incrementalShare() {
        val peer = server(1 to get(), 3 to get())
        peer.core.setPriority(1, urgency = 3, incremental = true)
        peer.core.setPriority(3, urgency = 3, incremental = true)
        assertEquals(listOf(1, 3, 1, 3, 1, 3, 1, 3), peer.drain(mapOf(1 to body, 3 to body)))
    }

    /** Section 10: early non-incremental responses must not starve an incremental one of the same urgency. */
    @Test
    fun incrementalAndNonIncrementalTakeTurns() {
        val peer = server(1 to get(), 3 to get())
        peer.core.setPriority(3, urgency = 3, incremental = true)
        assertEquals(listOf(3, 1, 3, 1, 3, 1, 3, 1), peer.drain(mapOf(1 to body, 3 to body)))
    }

    /** Section 10.1: "servers SHOULD allocate some amount of bandwidths to streams acting as tunnels". */
    @Test
    fun tunnelGetsShareBehindMoreUrgentResponse() {
        val connect = listOf(":method" to "CONNECT", ":authority" to "example.com:443")
        val peer = server(1 to connect, 3 to get())
        peer.core.setPriority(1, urgency = 7, incremental = false)
        peer.core.setPriority(3, urgency = 0, incremental = false)
        val order = peer.drain(mapOf(1 to 2 * frame, 3 to 64 * frame))
        assertEquals(DataScheduler.TUNNEL_TURN - 1, order.indexOf(1), "the tunnel's first frame: $order")
        assertEquals(2, order.count { it == 1 })
        assertTrue(order.lastIndexOf(1) < 2 * DataScheduler.TUNNEL_TURN, "$order")
    }

    /** An ordinary less urgent response gets nothing while a more urgent one has data (urgency first). */
    @Test
    fun negative_lessUrgentResponseGetsNoShare() {
        val peer = server(1 to get(), 3 to get())
        peer.core.setPriority(1, urgency = 7, incremental = false)
        peer.core.setPriority(3, urgency = 0, incremental = false)
        assertEquals(List(64) { 3 } + listOf(1, 1), peer.drain(mapOf(1 to 2 * frame, 3 to 64 * frame)))
    }

    /**
     * A more urgent response whose writer does not hand over its next frame holds the others back only for a moment: the
     * connection stays busy (work-conserving), not idle until that writer comes back.
     */
    @Test
    fun negative_silentUrgentWriterDoesNotStallTheConnection() {
        val peer = server(1 to get(), 3 to get())
        peer.core.setPriority(3, urgency = 0, incremental = false)
        val order = peer.drain(mapOf(1 to body, 3 to body)) { it != 3 }
        assertEquals(listOf(3) + List(4) { 1 }, order)
    }

    /** A priority change applies to the frames that follow. */
    @Test
    fun priorityChangeApplies() {
        val peer = server(1 to get(), 3 to get())
        peer.core.setPriority(3, urgency = 0, incremental = false)
        var changed = false
        val order =
            peer.drain(mapOf(1 to body, 3 to body)) {
                if (!changed) {
                    changed = true
                    peer.core.setPriority(3, urgency = 7, incremental = false)
                }
                true
            }
        assertEquals(listOf(3) + List(4) { 1 } + List(3) { 3 }, order)
    }
}

/**
 * RFC 9218 section 2.1.1: "until the client receives the SETTINGS frame from the server, the client SHOULD send both the
 * HTTP/2 priority signals and the signals of this prioritization scheme"; "Once the client receives the first SETTINGS
 * frame that contains the SETTINGS_NO_RFC7540_PRIORITIES parameter with a value of 1, it SHOULD stop sending the HTTP/2
 * priority signals." The RFC 7540 signal of a request: dependency 0, not exclusive, a weight from its urgency.
 */
class ClientRfc7540SignalTest {
    private fun RawH2Peer.request(
        urgency: Int,
        incremental: Boolean = false,
    ): Frame.Headers {
        val id = core.openStream(GET, endStream = true, urgency = urgency, incremental = incremental)
        return read().filterIsInstance<Frame.Headers>().single { it.streamId == id }
    }

    @Test
    fun weightFollowsUrgency() {
        assertEquals(listOf(256, 220, 183, 147, 110, 74, 37, 1), (0..7).map { rfc7540Weight(it) })
    }

    @Test
    fun signalsBeforeTheServersSettings() {
        val c = RawH2Peer(Role.CLIENT)
        val h = c.request(urgency = 0)
        assertEquals(0, h.dependency)
        assertEquals(false, h.exclusive)
        assertEquals(256, h.weight)
        assertEquals(147, c.request(urgency = 3, incremental = true).weight)
    }

    @Test
    fun signalsGoOnWhenTheServerKeepsRfc7540Priorities() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake() // no SETTINGS_NO_RFC7540_PRIORITIES: initial value 0
        assertEquals(37, c.request(urgency = 6).weight)
        val zero = RawH2Peer(Role.CLIENT)
        zero.handshake(FrameEncoder.settings(intArrayOf(SettingId.NO_RFC7540_PRIORITIES), longArrayOf(0)))
        assertEquals(0, zero.request(urgency = 1).dependency)
    }

    @Test
    fun negative_noSignalsOnceTheServerIgnoresThem() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(FrameEncoder.settings(intArrayOf(SettingId.NO_RFC7540_PRIORITIES), longArrayOf(1)))
        assertEquals(-1, c.request(urgency = 0).dependency)
    }
}

/** RFC 9218 section 7.1 (and the buffering of section 7) on a server, and the client that sends the frame. */
class PriorityUpdateTest {
    private fun update(
        id: Int,
        value: String,
    ) = FrameEncoder.priorityUpdate(id, value)

    private fun RawH2Peer.updates() = events().filterIsInstance<H2Event.PriorityUpdate>().map { it.streamId to it.value }

    @Test
    fun appliedToAnOpenStream() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(s.headers(1, endStream = false))
        s.events()
        s.send(update(1, "u=1"))
        assertEquals(listOf(1 to "u=1"), s.updates())
    }

    /** "Servers SHOULD buffer the most recently received PRIORITY_UPDATE frame and apply it once the referenced stream is opened." */
    @Test
    fun earlyUpdateArrivesWithTheRequest() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(update(3, "u=6"), update(3, "u=0, i"))
        s.send(s.headers(1), s.headers(3))
        val heads = s.events().filterIsInstance<H2Event.HeadersReceived>().associate { it.streamId to it.priorityUpdate }
        assertEquals(mapOf(1 to null, 3 to "u=0, i"), heads)
    }

    /** "Servers can discard frames where the prioritized stream ID refers to a stream in the [...] closed state". */
    @Test
    fun updateForAClosedStreamIsDiscarded() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(s.headers(1))
        s.events()
        s.core.sendHeaders(1, OK, endStream = true)
        s.read()
        s.send(update(1, "u=1"), update(5, "u=1"), s.headers(7))
        s.send(update(5, "u=2")) // skipped by stream 7: closed (RFC 9113 section 5.1.1)
        assertTrue(s.updates().isEmpty())
        assertTrue(!s.core.isClosed)
    }

    /** "The Stream Identifier field [...] MUST be zero (0x0)": anything else is a PROTOCOL_ERROR connection error. */
    @Test
    fun negative_onARequestStream() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(s.headers(1, endStream = false), FrameEncoder.raw(FrameType.PRIORITY_UPDATE, 0, 1, update(1, "u=1").copyOfRange(9, 16)))
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    /** "If a PRIORITY_UPDATE frame is received with a prioritized stream ID of 0x0, the recipient MUST respond with a connection error". */
    @Test
    fun negative_forStreamZero() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(update(0, "u=1"))
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    /** "Servers that receive a PRIORITY_UPDATE for a push stream in the idle state MUST respond with a connection error": we never push. */
    @Test
    fun negative_forAPushStream() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(update(2, "u=1"))
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    /**
     * "The number of streams that have been prioritized but remain in the 'idle' state plus the number of active streams
     * [...] MUST NOT exceed the value of the SETTINGS_MAX_CONCURRENT_STREAMS parameter. Servers that receive such a
     * PRIORITY_UPDATE MUST respond with a connection error of type PROTOCOL_ERROR." Idle streams that a newer stream
     * closed no longer count.
     */
    @Test
    fun negative_tooManyPrioritizedIdleStreams() {
        val s = RawH2Peer(Role.SERVER, io.kuicksilver.http2.Http2Settings(maxConcurrentStreams = 2))
        s.handshake()
        s.send(update(1, "u=1"), s.headers(3, endStream = false)) // 1 is closed now: only 3 counts
        s.send(update(5, "u=1"))
        assertTrue(!s.core.isClosed)
        s.send(update(7, "u=1"))
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun negative_tooShort() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake()
        s.send(FrameEncoder.raw(FrameType.PRIORITY_UPDATE, 0, 0, byteArrayOf(0, 0, 1)))
        s.assertConnectionError(Http2ErrorCode.FRAME_SIZE_ERROR)
    }

    /**
     * The client sends the frame for a stream that may still receive data, before the server's SETTINGS and while they
     * say SETTINGS_NO_RFC7540_PRIORITIES = 1; with 0 or without it "it SHOULD stop sending PRIORITY_UPDATE frames"
     * (section 2.1.1).
     */
    @Test
    fun clientSendsUpdates() {
        val c = RawH2Peer(Role.CLIENT)
        val id = c.core.openStream(GET, endStream = true)
        c.read()
        assertTrue(c.core.priorityUpdate(id, "u=1"))
        c.handshake(FrameEncoder.settings(intArrayOf(SettingId.NO_RFC7540_PRIORITIES), longArrayOf(1)))
        assertTrue(c.core.priorityUpdate(id, "u=2"))
        val sent = c.read().filterIsInstance<Frame.PriorityUpdate>().map { it.prioritizedStreamId to it.value }
        assertEquals(
            listOf(id to "u=1", id to "u=2"),
            (c.written.filterIsInstance<Frame.PriorityUpdate>()).map {
                it.prioritizedStreamId to
                    it.value
            },
        )
        assertTrue(sent.isNotEmpty())
        c.send(c.headers(id, OK, endStream = true))
        c.events()
        assertEquals(false, c.core.priorityUpdate(id, "u=3")) // closed: no more data comes
        val legacy = RawH2Peer(Role.CLIENT)
        legacy.handshake()
        val id2 = legacy.core.openStream(GET, endStream = true)
        assertEquals(false, legacy.core.priorityUpdate(id2, "u=1"))
    }
}
