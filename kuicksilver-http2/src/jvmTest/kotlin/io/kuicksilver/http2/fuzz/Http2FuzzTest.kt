// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.H2ConnectionError
import io.kuicksilver.http2.frame.H2StreamError
import io.kuicksilver.http2.hpack.HpackDecoder
import io.kuicksilver.http2.hpack.HpackError
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertTrue

/**
 * Fuzz target `frames`: input = [split byte][frames]. The bytes go into a FrameDecoder with a 16 KiB SETTINGS_MAX_FRAME_SIZE
 * in pieces of 1 + (split byte) bytes; only the decoder's own errors may escape, no payload is larger than the limit and
 * the decoder never allocates more than the input it was given plus one frame of at most the limit (a frame's buffer is
 * sized from its checked length when its header arrives).
 */
class H2FrameFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun frames(data: ByteArray) {
        if (data.isEmpty()) return
        val piece = 1 + (data[0].toInt() and 0xff)
        val d = FrameDecoder(16_384)
        var p = 1
        try {
            while (p < data.size) {
                val n = minOf(piece, data.size - p)
                var used = 0
                while (used < n) {
                    used += d.feed(data, p + used, n - used)
                    val f =
                        try {
                            d.next()
                        } catch (_: H2StreamError) {
                            null
                        }
                    when (f) {
                        is Frame.Data -> {
                            assertTrue(f.data.size <= 16_384 && f.flowLength <= 16_384)
                        }

                        is Frame.Headers -> {
                            assertTrue(f.fragment.size <= 16_384)
                        }

                        is Frame.Continuation -> {
                            assertTrue(f.fragment.size <= 16_384)
                        }

                        is Frame.Settings -> {
                            assertTrue(f.ids.size == f.values.size)
                        }

                        else -> {}
                    }
                }
                p += n
            }
        } catch (_: H2ConnectionError) {
        }
        assertTrue(d.allocatedBytes <= data.size + 16_384, "allocated ${d.allocatedBytes} for ${data.size} input bytes")
    }
}

/**
 * Fuzz target `hpackDecode`: input = [settings byte][block length, 2 bytes][block 1][block 2]. Two field blocks through one
 * decoder (the dynamic table carries over); the low bits of the first byte pick the table size and the list limit. Only
 * HpackError may escape; the fields that reach the sink never pass the list limit, and literals never allocate more than
 * the block's length times 8/5 (the densest Huffman code).
 */
class HpackDecodeFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun hpackDecode(data: ByteArray) {
        if (data.size < 3) return
        val table = intArrayOf(0, 256, 4_096, 65_536)[data[0].toInt() and 3]
        val limit = intArrayOf(64, 1_024, 16_384, 65_536)[(data[0].toInt() shr 2) and 3]
        val d = HpackDecoder(maxTableSize = table, maxHeaderListSize = limit)
        val split = minOf(((data[1].toInt() and 0xff) shl 8) or (data[2].toInt() and 0xff), data.size - 3)
        try {
            for ((off, len) in listOf(3 to split, 3 + split to data.size - 3 - split)) {
                var listSize = 0L
                d.decode(data, off, len) { n, v -> listSize += n.length + v.length + 32 }
                assertTrue(listSize <= limit, "list of $listSize above $limit")
                assertTrue(d.lastAllocated <= len.toLong() * 8 / 5 + 8, "allocated ${d.lastAllocated} for a block of $len")
            }
        } catch (_: HpackError) {
        }
    }
}

/**
 * Fuzz target `connectionServer`: input = [split byte][bytes after the client preface]. A server core fed the input in
 * pieces of 1 + (split byte) bytes, one virtual millisecond apart, driven like an engine: every request gets response
 * headers and a body sent as the windows allow, streams are released when done or, when reset, one piece later (the
 * engine's handler of a reset stream is cancelled, and returns, after the core reported the reset), content is consumed,
 * output is drained and decoded as the client would, with its own HPACK decoder. Nothing may escape the core; its state
 * stays within its settings; handlers that have not returned, reset ones included, never pass SETTINGS_MAX_CONCURRENT_STREAMS
 * (Rapid Reset, CVE-2023-44487; MadeYouReset, CVE-2025-8671); the connection send window is conserved (credit = window
 * left + DATA queued + DATA written: dropped DATA gives its window back); every field block on the wire decodes to the
 * response the driver sent on that stream.
 */
class H2ConnectionFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    private class Wire {
        val frames = FrameDecoder(16_777_215)
        val hpack = HpackDecoder(maxTableSize = 4_096, maxHeaderListSize = 1 shl 20)
        var block = ByteArray(0)
        var blockStream = 0

        /** Decodes the core's output; every field block must be one the driver sent on that stream. */
        fun read(
            bytes: ByteArray,
            n: Int,
            expected: Map<Int, List<Pair<String, String>>>,
        ) {
            var p = 0
            while (p < n) {
                p += frames.feed(bytes, p, n - p)
                val f = frames.next() ?: continue
                if (f is Frame.Headers) {
                    blockStream = f.streamId
                    block = f.fragment
                    if (f.endHeaders) check(expected)
                } else if (f is Frame.Continuation) {
                    block += f.fragment
                    if (f.endHeaders) check(expected)
                }
            }
        }

        private fun check(expected: Map<Int, List<Pair<String, String>>>) {
            val got = mutableListOf<Pair<String, String>>()
            hpack.decode(block) { n, v -> got += n to v } // an HpackError here is a finding: the encoder drifted
            assertTrue(got == expected[blockStream], "stream $blockStream decoded $got, sent ${expected[blockStream]}")
        }
    }

    @FuzzTest(maxDuration = "60s")
    fun connectionServer(data: ByteArray) {
        if (data.isEmpty()) return
        val settings = io.kuicksilver.http2.Http2Settings(maxConcurrentStreams = 8, maxHeaderListSize = 4_096, maxControlFramesQueued = 64)
        val core =
            io.kuicksilver.http2.core
                .H2ConnectionCore(io.kuicksilver.http2.core.Role.SERVER, settings, 0)
        val out = ByteArray(4_096)
        val wire = Wire()
        val sent = HashMap<Int, List<Pair<String, String>>>()
        val bodyLeft = HashMap<Int, Int>()
        val handlers = Handlers()
        val piece = 1 + (data[0].toInt() and 0xff)
        var now = 0L
        core.receive(io.kuicksilver.http2.frame.H2.PREFACE, 0, 24, now)
        var p = 1
        while (p < data.size && !core.isClosed) {
            val n = minOf(piece, data.size - p)
            now += 1_000_000
            handlers.returnCancelled(core) // the handlers of the streams reset in the previous piece return now
            core.receive(data, p, n, now)
            p += n
            drive(core, now, sent, bodyLeft, handlers, 1 + (data[p - 1].toInt() and 0xff) * 64) // never empty: a body waits for window
            assertTrue(handlers.running.size <= 8, "handlers running ${handlers.running.size}, reset ones included")
            assertTrue(core.activeStreams <= 8, "streams ${core.activeStreams}")
            assertTrue(core.controlQueued <= 64, "control frames ${core.controlQueued}")
            assertTrue(core.blockBufferCapacity <= 2 * 4_096, "field block buffer ${core.blockBufferCapacity}")
            if (!core.isClosed) assertTrue(core.sendWindowConserved, "connection send window not conserved")
            while (true) {
                val k = core.poll(out, 0, now)
                if (k == 0) break
                wire.read(out, k, sent)
            }
            core.nextTimeout()?.let { if (it <= now + 10_000_000_000) core.onTimeout(it) }
        }
    }

    /** The model of the engine's handlers: one per request until it returns; a reset one returns a piece later. */
    private class Handlers {
        val running = HashSet<Int>()
        private val cancelled = ArrayList<Int>()

        fun start(id: Int) {
            running += id
        }

        /** The handler returned: the stream is released. */
        fun done(
            core: io.kuicksilver.http2.core.H2ConnectionCore,
            id: Int,
        ) {
            running -= id
            cancelled -= id
            core.release(id)
        }

        /** The stream was reset: its handler is cancelled and returns later. */
        fun cancel(id: Int) {
            if (id in running && id !in cancelled) cancelled += id
        }

        fun returnCancelled(core: io.kuicksilver.http2.core.H2ConnectionCore) {
            for (id in cancelled.toList()) done(core, id)
        }
    }

    private fun drive(
        core: io.kuicksilver.http2.core.H2ConnectionCore,
        now: Long,
        sent: MutableMap<Int, List<Pair<String, String>>>,
        bodyLeft: MutableMap<Int, Int>,
        handlers: Handlers,
        bodySize: Int,
    ) {
        val body = ByteArray(16_384)

        fun pump(id: Int) {
            val left = bodyLeft[id] ?: return
            val n =
                try {
                    core.sendData(id, body, 0, minOf(left, body.size), endStream = true)
                } catch (_: IllegalStateException) {
                    bodyLeft.remove(id) // closed meanwhile: its reset event cancels the handler
                    return
                }
            if (n == left) {
                bodyLeft.remove(id)
                handlers.done(core, id)
            } else {
                bodyLeft[id] = left - n
            }
        }
        while (true) {
            when (val e = core.nextEvent() ?: return) {
                is io.kuicksilver.http2.core.H2Event.HeadersReceived -> {
                    if (sent.containsKey(e.streamId)) continue // trailers of a request we answered already
                    handlers.start(e.streamId)
                    val fields = listOf(":status" to (if (e.tooLarge) "431" else "200"))
                    try {
                        core.sendHeaders(e.streamId, fields, endStream = false)
                        sent[e.streamId] = fields
                        bodyLeft[e.streamId] = bodySize
                        pump(e.streamId)
                    } catch (_: IllegalStateException) {
                        // the stream was reset meanwhile: the driver's call is refused, and the handler, busy until it
                        // notices its cancellation, returns a piece later
                        handlers.cancel(e.streamId)
                    } catch (_: io.kuicksilver.http2.core.H2HeaderListTooLarge) {
                        // the peer's SETTINGS_MAX_HEADER_LIST_SIZE refuses even this response: an engine resets the stream
                        core.reset(e.streamId, io.kuicksilver.http2.Http2ErrorCode.INTERNAL_ERROR, now)
                        handlers.done(core, e.streamId)
                    }
                }

                is io.kuicksilver.http2.core.H2Event.WindowAvailable -> {
                    pump(e.streamId)
                }

                is io.kuicksilver.http2.core.H2Event.Data -> {
                    core.consumed(e.streamId, e.data.size.toLong(), now)
                }

                is io.kuicksilver.http2.core.H2Event.StreamReset -> {
                    bodyLeft.remove(e.streamId)
                    // a stream the driver never took (refused, or reset before its HEADERS were reported) has no handler
                    if (e.streamId in handlers.running) handlers.cancel(e.streamId) else core.release(e.streamId)
                }

                else -> {}
            }
        }
    }
}

/**
 * Fuzz target `connectionClient`: input = [split byte][streams byte][bytes from the server after its SETTINGS]. A client core
 * opens 1 + (streams byte % 8) requests (every third a POST with a body sent as the windows allow), then reads the input
 * in pieces of 1 + (split byte) bytes, one virtual millisecond apart, driven like the engine: every field section goes
 * through the RFC 9113 section 8 checks (H2Messages; a malformed one resets its stream with PROTOCOL_ERROR, a too large
 * one with CANCEL), content is consumed, finished and reset streams are released, output is drained. Nothing may escape
 * the core or the checks but their own errors; its state stays within its settings, and the connection send window is
 * conserved.
 */
class H2ClientConnectionFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun connectionClient(data: ByteArray) {
        if (data.size < 2) return
        val settings = io.kuicksilver.http2.Http2Settings(maxHeaderListSize = 4_096, maxControlFramesQueued = 64)
        val core =
            io.kuicksilver.http2.core
                .H2ConnectionCore(io.kuicksilver.http2.core.Role.CLIENT, settings, 0)
        val out = ByteArray(4_096)
        val body = ByteArray(16_384)
        val bodyLeft = HashMap<Int, Int>()
        val finalSeen = HashSet<Int>()
        var now = 0L
        // the server's preface (an empty SETTINGS frame) is not fuzzed: the core refuses anything else first (section 3.4)
        val preface =
            io.kuicksilver.http2.frame.FrameEncoder
                .settings(IntArray(0), LongArray(0))
        core.receive(preface, 0, preface.size, now)
        val streams = 1 + (data[1].toInt() and 0xff) % 8
        val opened = ArrayList<Int>()
        repeat(streams) { i ->
            val post = i % 3 == 2
            val fields =
                listOf(":method" to (if (post) "POST" else "GET"), ":scheme" to "https", ":authority" to "example.com", ":path" to "/$i")
            val id = core.openStream(fields, endStream = !post)
            opened += id
            if (post) bodyLeft[id] = 100_000
        }

        fun pump(id: Int) {
            val left = bodyLeft[id] ?: return
            val n =
                try {
                    core.sendData(id, body, 0, minOf(left, body.size), endStream = true)
                } catch (_: IllegalStateException) {
                    bodyLeft.remove(id) // reset meanwhile
                    return
                }
            if (n == left) bodyLeft.remove(id) else bodyLeft[id] = left - n
        }
        for (id in opened) pump(id)

        fun drive() {
            while (true) {
                when (val e = core.nextEvent() ?: return) {
                    is io.kuicksilver.http2.core.H2Event.HeadersReceived -> {
                        try {
                            when {
                                e.tooLarge -> {
                                    core.reset(e.streamId, io.kuicksilver.http2.Http2ErrorCode.CANCEL, now)
                                }

                                e.streamId in finalSeen -> {
                                    io.kuicksilver.http2.message.H2Messages
                                        .parseTrailers(e.fields)
                                }

                                else -> {
                                    val r =
                                        io.kuicksilver.http2.message.H2Messages
                                            .parseResponse(e.fields)
                                    if (r.status >= 200) finalSeen += e.streamId
                                }
                            }
                        } catch (_: io.kuicksilver.http2.message.MalformedMessage) {
                            core.reset(e.streamId, io.kuicksilver.http2.Http2ErrorCode.PROTOCOL_ERROR, now)
                        }
                        if (e.endStream) core.release(e.streamId)
                    }

                    is io.kuicksilver.http2.core.H2Event.Data -> {
                        core.consumed(e.streamId, e.data.size.toLong(), now)
                        if (e.endStream) core.release(e.streamId)
                    }

                    is io.kuicksilver.http2.core.H2Event.WindowAvailable -> {
                        pump(e.streamId)
                    }

                    is io.kuicksilver.http2.core.H2Event.StreamReset -> {
                        bodyLeft.remove(e.streamId)
                        core.release(e.streamId)
                    }

                    else -> {}
                }
            }
        }
        val piece = 1 + (data[0].toInt() and 0xff)
        var p = 2
        while (p < data.size && !core.isClosed) {
            val n = minOf(piece, data.size - p)
            now += 1_000_000
            core.receive(data, p, n, now)
            p += n
            drive()
            assertTrue(core.activeStreams <= streams, "streams ${core.activeStreams}")
            assertTrue(core.controlQueued <= 64, "control frames ${core.controlQueued}")
            assertTrue(core.blockBufferCapacity <= 2 * 4_096, "field block buffer ${core.blockBufferCapacity}")
            if (!core.isClosed) assertTrue(core.sendWindowConserved, "connection send window not conserved")
            while (core.poll(out, 0, now) > 0) continue
            core.nextTimeout()?.let { if (it <= now + 10_000_000_000) core.onTimeout(it) }
        }
    }
}

/**
 * Fuzz target `hpackRoundTrip` (differential, at the HPACK level; the connection-level check of the same property is in
 * `connectionServer`): the input is cut into field lists and peer table size changes; each list is encoded by our encoder
 * and decoded by a separate decoder that learns the table size as the peer would. The decoded list must equal the encoded
 * one, block after block.
 */
class HpackRoundTripFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun hpackRoundTrip(data: ByteArray) {
        val enc =
            io.kuicksilver.http2.hpack
                .HpackEncoder()
        val dec = HpackDecoder(maxTableSize = 4_096, maxHeaderListSize = 1 shl 20)
        var p = 0

        fun next(): Int = if (p < data.size) data[p++].toInt() and 0xff else -1

        fun string(): String {
            val n = next().coerceAtLeast(0) % 40
            val c = CharArray(n) { Char(next().coerceAtLeast(0)) }
            return c.concatToString()
        }
        val names = listOf(":path", "authorization", "cookie", "set-cookie", "x-a", "content-type", "date")
        while (p < data.size) {
            val op = next()
            if (op == 0xff) {
                val size = (next().coerceAtLeast(0) shl 4).coerceAtMost(4_096)
                enc.setPeerMaxTableSize(size.toLong()) // the peer lowered or raised SETTINGS_HEADER_TABLE_SIZE...
                dec.setMaxTableSize(size) // ...and our acknowledgement went out before the next block
                continue
            }
            val fields = List(op % 8) { (if (next() and 1 == 0) names[next().coerceAtLeast(0) % names.size] else string()) to string() }
            val block = enc.encode(fields)
            val got = mutableListOf<Pair<String, String>>()
            dec.decode(block) { n, v -> got += n to v }
            assertTrue(got == fields, "decoded $got, encoded $fields")
        }
    }
}
