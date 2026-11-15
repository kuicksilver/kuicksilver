// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.SettingId
import java.io.File
import java.util.Locale
import kotlin.test.Test

/**
 * A measurement, not a test: it returns at once unless `KSL_BENCH_H2_HELD_ACK` names an output CSV file
 * (`tools/bench/h2-held-ack.sh` sets it and runs it on two revisions). It measures what a SETTINGS acknowledgement held
 * behind DATA (RFC 9113 section 6.5.3) costs an urgent stream, and how long the acknowledgement waits. A server core and a
 * client core are joined in memory by a server-to-client link of a fixed rate (virtual time in ticks of [TICK_NANOS];
 * the client-to-server direction is unlimited). [bulk] urgency-7 streams have endless bodies, and an urgency-0 request
 * asks for a 1 KiB response every 5 ms. With [shrink], the client's side sends a SETTINGS every [SHRINK_EVERY_NANOS] that
 * alternately halves SETTINGS_INITIAL_WINDOW_SIZE (4 MiB to 2 MiB) and restores it, so every second acknowledgement waits
 * for the DATA the bulk streams already queued. An urgent response's delay runs from the server queueing its DATA to the
 * client receiving it; an acknowledgement's from the SETTINGS reaching the server to the acknowledgement crossing the link.
 */
class HeldAckInversionBench {
    @Test
    fun measure() {
        val out = System.getenv("KSL_BENCH_H2_HELD_ACK") ?: return
        val label = System.getenv("KSL_BENCH_H2_HELD_ACK_LABEL") ?: "tree"
        val rows = mutableListOf<String>()
        for (mbit in listOf(100, 1_000)) {
            for (bulk in listOf(1, 4, 16)) {
                for (shrink in listOf(false, true)) {
                    val (urgent, acks) = run(mbit, bulk, shrink)
                    rows += "$label,$mbit,$bulk,$shrink,${urgent.size},${stats(urgent)},${acks.size},${stats(acks)}"
                }
            }
        }
        File(out).appendText(rows.joinToString("\n", postfix = "\n"))
    }

    /** p50, p99 and max in milliseconds, or empty fields. */
    private fun stats(v: List<Long>): String {
        if (v.isEmpty()) return ",,"
        val d = v.sorted()

        fun p(q: Double) = d[minOf(d.size - 1, (q * d.size).toInt())] / 1e6
        return "%.3f,%.3f,%.3f".format(Locale.ROOT, p(0.5), p(0.99), d.last() / 1e6)
    }

    private fun run(
        mbit: Int,
        bulk: Int,
        shrink: Boolean,
    ): Pair<List<Long>, List<Long>> {
        var now = 0L
        val server = H2ConnectionCore(Role.SERVER, Http2Settings(), now)
        val client =
            H2ConnectionCore(
                Role.CLIENT,
                Http2Settings(initialStreamWindow = BIG_WINDOW, maxStreamWindow = BIG_WINDOW, initialConnectionWindow = 15_728_640),
                now,
            )
        val link = FrameDecoder(H2.MAX_MAX_FRAME_SIZE) // watches the link for the acknowledgements
        var prefaceSeen = false
        val linkBuf = ByteArray((mbit * 1_000_000L / 8 * TICK_NANOS / 1_000_000_000L).toInt())
        val upBuf = ByteArray(1 shl 20)
        val chunk = ByteArray(65_536)
        val small = ByteArray(1_024)
        val bulkStreams = mutableListOf<Int>()
        val queuedAt = HashMap<Int, Long>()
        val settingsAt = ArrayDeque<Long>()
        val urgent = mutableListOf<Long>()
        val acks = mutableListOf<Long>()
        var nextUrgent = WARMUP_NANOS
        var nextShrink = WARMUP_NANOS
        var smaller = false
        repeat(bulk) { client.openStream(request("/bulk/$it"), endStream = true, urgency = 7) }
        while (now < WARMUP_NANOS + DURATION_NANOS) {
            while (true) {
                val n = client.poll(upBuf, 0, now)
                if (n == 0) break
                server.receive(upBuf, 0, n, now)
            }
            if (shrink && now >= nextShrink) {
                // after the client's whole frames; the client's core ignores the acknowledgement it did not ask for
                val iws = if (smaller) BIG_WINDOW.toLong() else BIG_WINDOW / 2L
                smaller = !smaller
                val f = FrameEncoder.settings(intArrayOf(SettingId.INITIAL_WINDOW_SIZE), longArrayOf(iws))
                server.receive(f, 0, f.size, now)
                settingsAt.addLast(now)
                nextShrink += SHRINK_EVERY_NANOS
            }
            while (true) {
                val e = server.nextEvent() ?: break
                if (e !is H2Event.HeadersReceived || !e.opening) continue
                val path = e.fields.first { it.first == ":path" }.second
                server.sendHeaders(e.streamId, OK, endStream = false)
                if (path.startsWith("/bulk/")) {
                    server.setPriority(e.streamId, 7, incremental = false)
                    bulkStreams += e.streamId
                } else {
                    server.setPriority(e.streamId, 0, incremental = false)
                    check(server.sendData(e.streamId, small, 0, small.size, endStream = true) == small.size)
                    server.release(e.streamId)
                    queuedAt[e.streamId] = now
                }
            }
            for (id in bulkStreams) server.sendData(id, chunk, 0, chunk.size, endStream = false) // always a frame ready
            val n = server.poll(linkBuf, 0, now)
            if (n > 0) {
                client.receive(linkBuf, 0, n, now)
                var p = 0
                while (p < n) {
                    p += link.feed(linkBuf, p, n - p)
                    while (true) {
                        val f = link.next() ?: break
                        if (f is Frame.Settings && f.ack) {
                            if (!prefaceSeen) prefaceSeen = true else settingsAt.removeFirstOrNull()?.let { acks += now - it }
                        }
                    }
                }
            }
            while (true) {
                val e = client.nextEvent() ?: break
                if (e !is H2Event.Data) continue
                client.consumed(e.streamId, e.data.size.toLong(), now)
                if (e.endStream) {
                    client.release(e.streamId)
                    queuedAt.remove(e.streamId)?.let { if (it >= WARMUP_NANOS) urgent += now - it }
                }
            }
            check(!server.isClosed && !client.isClosed) { "connection closed" }
            if (now >= nextUrgent) {
                client.openStream(request("/urgent"), endStream = true, urgency = 0)
                nextUrgent += URGENT_EVERY_NANOS
            }
            now += TICK_NANOS
        }
        return urgent to acks
    }

    private fun request(path: String) = GET.map { if (it.first == ":path") ":path" to path else it }

    private companion object {
        const val TICK_NANOS = 50_000L
        const val WARMUP_NANOS = 200_000_000L
        const val DURATION_NANOS = 2_000_000_000L
        const val URGENT_EVERY_NANOS = 5_000_000L
        const val SHRINK_EVERY_NANOS = 20_000_000L
        const val BIG_WINDOW = 4_194_304
    }
}
