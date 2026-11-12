// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
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
