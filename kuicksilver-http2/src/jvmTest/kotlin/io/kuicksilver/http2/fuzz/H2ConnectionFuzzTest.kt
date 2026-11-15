// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.core.H2ConnectionCore
import io.kuicksilver.http2.core.H2ConnectionUnusable
import io.kuicksilver.http2.core.H2Event
import io.kuicksilver.http2.core.H2HeaderListTooLarge
import io.kuicksilver.http2.core.H2StreamLimit
import io.kuicksilver.http2.core.Role
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.message.H2Messages
import io.kuicksilver.http2.message.MalformedMessage
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.TestInfo
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The mode byte of the stateful targets: the low two bits pick the limits ([settings]), bit 2 Extended CONNECT (RFC
 * 8441: a server advertises it, a client opens a WebSocket stream once the server did), bits 3 and 4 how the peer reads
 * ([Drain]), bit 5 a clock of one second per piece instead of one millisecond (the budgets refill, the SETTINGS
 * acknowledgement, field block and graceful GOAWAY deadlines pass), bit 6 the driver's own actions (PING, GOAWAY,
 * resets, priorities, trailers or more requests) taken from the last byte of each piece, bit 7 (client) the server's
 * frames before the client's first flight is read, so they can reach requests the server has not seen. Mode 0 is the
 * drive of the first versions of these targets.
 */
internal class Mode(
    m: Int,
) {
    val settings: Http2Settings = settings(m and 3)
    val connect = m and 4 != 0
    val drain = Drain.entries[(m shr 3) and 3]
    val tick = if (m and 0x20 != 0) 1_000_000_000L else 1_000_000L
    val actions = m and 0x40 != 0
    val serverFirst = m and 0x80 != 0

    enum class Drain {
        /** Everything we wrote is read after every piece. */
        EVERY_PIECE,

        /** ... after every fourth piece. */
        EVERY_FOURTH,

        /** ... only after the whole input: the peer floods without reading. */
        AT_THE_END,

        /** One read of at most 64 bytes per piece: frames are left partly written between pieces. */
        SHORT_READS,
    }

    companion object {
        fun settings(preset: Int): Http2Settings =
            when (preset) {
                0 -> {
                    Http2Settings(maxConcurrentStreams = 8, maxHeaderListSize = 4_096, maxControlFramesQueued = 64)
                }

                // every flood limit small enough to be reached by a short input
                1 -> {
                    Http2Settings(
                        maxConcurrentStreams = 2,
                        maxHeaderListSize = 256,
                        maxControlFramesQueued = 6,
                        maxContinuationFrames = 2,
                        maxEmptyFrames = 3,
                        resetBurst = 4,
                        resetsPerSecond = 1,
                        glitchBurst = 16,
                        glitchesPerSecond = 1,
                        initialStreamWindow = 100,
                        maxStreamWindow = 400,
                        settingsAckTimeout = 3.seconds,
                        maxHeaderBlockTime = 2.seconds,
                    )
                }

                // small receive windows (FLOW_CONTROL_ERROR within reach) and no dynamic table towards us
                2 -> {
                    Http2Settings(
                        maxConcurrentStreams = 8,
                        headerTableSize = 0,
                        maxHeaderListSize = 1_024,
                        maxControlFramesQueued = 64,
                        initialStreamWindow = 16,
                        maxStreamWindow = 64,
                        initialConnectionWindow = 65_535,
                        maxConnectionWindow = 65_535,
                    )
                }

                // large frames and table, the default limits otherwise
                else -> {
                    Http2Settings(maxFrameSize = 65_536, headerTableSize = 65_536)
                }
            }
    }
}

/** Polls what [core] wrote into the [mirror] as the peer reads it: all of it, or one read of at most [max] bytes. */
private fun drain(
    core: H2ConnectionCore,
    mirror: WireMirror,
    now: Long,
    max: Int = Int.MAX_VALUE,
) {
    val out = ByteArray(minOf(max, 4_096))
    while (true) {
        val k = core.poll(out, 0, now)
        if (k == 0) return
        mirror.ours(out, 0, k)
        if (max != Int.MAX_VALUE) return
    }
}

private fun Mode.drainAfter(
    piece: Int,
    core: H2ConnectionCore,
    mirror: WireMirror,
    now: Long,
) {
    when (drain) {
        Mode.Drain.EVERY_PIECE -> {
            drain(core, mirror, now)
        }

        Mode.Drain.EVERY_FOURTH -> {
            if (piece % 4 == 0) drain(core, mirror, now)
        }

        Mode.Drain.AT_THE_END -> {}

        Mode.Drain.SHORT_READS -> {
            drain(core, mirror, now, 64)
        }
    }
}

/** What the core must hold to after every piece, whoever drives it. */
private fun H2ConnectionCore.checkBounds() {
    assertTrue(controlQueued <= settings.maxControlFramesQueued, "control frames $controlQueued")
    assertTrue(blockBufferCapacity <= 2 * settings.maxHeaderListSize, "field block buffer $blockBufferCapacity")
    if (!isClosed) assertTrue(sendWindowConserved, "connection send window not conserved")
}

/**
 * Fuzz target `connectionServer`: input = [split byte][mode byte ([Mode])][bytes after the client preface]. A server core
 * fed the input in pieces of 1 + (split byte) bytes, a tick of virtual time apart, driven like the engine: every request
 * goes through the RFC 9113 section 8 checks (a malformed one is reset with PROTOCOL_ERROR as an error of the peer's, a
 * too large one answered with 431), an Extended CONNECT is taken where advertised, every request gets response headers and
 * a body (and trailers, with the driver's actions) sent as the windows allow, streams are released when done or, when
 * reset, one piece later (the engine's handler of a reset stream is cancelled, and returns, after the core reported the
 * reset), content is consumed, timeouts fire when due, and the output is read as the mode says by a [WireMirror], which
 * checks it against the client's frames. Nothing may escape the core but the mirror's and these findings; its state stays
 * within its settings; handlers that have not returned, reset ones included, never pass SETTINGS_MAX_CONCURRENT_STREAMS
 * (Rapid Reset, CVE-2023-44487; MadeYouReset, CVE-2025-8671); the connection send window is conserved (credit = window
 * left + DATA queued + DATA written: dropped DATA gives its window back).
 */
class H2ConnectionFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun connectionServer(data: ByteArray) {
        if (data.size < 2) return
        val mode = Mode(data[1].toInt() and 0xff)
        val settings = mode.settings
        val core = H2ConnectionCore(Role.SERVER, settings, 0, enableConnectProtocol = mode.connect)
        reach?.watch(core)
        val mirror = WireMirror(client = false, settings)
        val d = ServerDriver(core, mirror, mode)
        val piece = 1 + (data[0].toInt() and 0xff)
        var now = 0L
        core.receive(H2.PREFACE, 0, 24, now)
        var p = 2
        var pieces = 0
        while (p < data.size && !core.isClosed) {
            val n = minOf(piece, data.size - p)
            now += mode.tick
            d.handlers.returnCancelled(core) // the handlers of the streams reset in the previous piece return now
            mirror.peer(data, p, n)
            core.receive(data, p, n, now)
            mirror.afterReceive(core.isClosed)
            p += n
            pieces++
            val last = data[p - 1].toInt() and 0xff
            d.drive(now, 1 + last * 64) // never empty: a body waits for window
            if (mode.actions) d.act(last, now)
            assertTrue(d.handlers.running.size <= settings.maxConcurrentStreams, "handlers running ${d.handlers.running.size}")
            assertTrue(core.activeStreams <= settings.maxConcurrentStreams, "streams ${core.activeStreams}")
            core.checkBounds()
            mode.drainAfter(pieces, core, mirror, now)
            core.nextTimeout()?.let { if (it <= now) core.onTimeout(now) }
        }
        d.drive(now, 1)
        drain(core, mirror, now)
        mirror.atEnd(core.isClosed)
        reach?.let { r -> generateSequence { core.nextEvent() }.forEach { r.event(it) } }
    }

    /** The model of the engine's handlers: one per request until it returns; a reset one returns a piece later. */
    private class Handlers {
        val running = LinkedHashSet<Int>()
        private val cancelled = ArrayList<Int>()

        fun start(id: Int) {
            running += id
        }

        /** The handler returned: the stream is released. */
        fun done(
            core: H2ConnectionCore,
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

        fun returnCancelled(core: H2ConnectionCore) {
            for (id in cancelled.toList()) done(core, id)
        }
    }

    private class ServerDriver(
        val core: H2ConnectionCore,
        val mirror: WireMirror,
        val mode: Mode,
    ) {
        val handlers = Handlers()
        private val answered = HashSet<Int>()
        private val bodyLeft = HashMap<Int, Int>()
        private val trailers = HashSet<Int>()
        private val body = ByteArray(16_384)

        fun respond(
            id: Int,
            fields: List<Pair<String, String>>,
            endStream: Boolean,
        ) {
            core.sendHeaders(id, fields, endStream)
            mirror.expect(id, fields)
        }

        fun pump(id: Int) {
            val left = bodyLeft[id] ?: return
            val end = id !in trailers
            val n =
                try {
                    core.sendData(id, body, 0, minOf(left, body.size), endStream = end)
                } catch (_: IllegalStateException) {
                    bodyLeft.remove(id) // closed meanwhile: its reset event cancels the handler
                    return
                }
            if (n < left) {
                bodyLeft[id] = left - n
                return
            }
            bodyLeft.remove(id)
            if (!end) {
                try {
                    respond(id, listOf("x-trailer" to "done"), endStream = true)
                } catch (_: IllegalStateException) {
                    return // reset meanwhile
                } catch (_: H2HeaderListTooLarge) {
                    core.reset(id, Http2ErrorCode.INTERNAL_ERROR, 0)
                }
            }
            handlers.done(core, id)
        }

        fun drive(
            now: Long,
            bodySize: Int,
        ) {
            while (true) {
                val e = core.nextEvent() ?: return
                reach?.event(e)
                when (e) {
                    is H2Event.HeadersReceived -> {
                        request(e, now, bodySize)
                    }

                    is H2Event.WindowAvailable -> {
                        pump(e.streamId)
                    }

                    is H2Event.Data -> {
                        core.consumed(e.streamId, e.data.size.toLong(), now)
                    }

                    is H2Event.StreamReset -> {
                        bodyLeft.remove(e.streamId)
                        // a stream the driver never took (refused, or reset before its HEADERS were reported) has no handler
                        if (e.streamId in handlers.running) handlers.cancel(e.streamId) else core.release(e.streamId)
                    }

                    else -> {}
                }
            }
        }

        private fun request(
            e: H2Event.HeadersReceived,
            now: Long,
            bodySize: Int,
        ) {
            if (!e.opening || e.streamId in answered) return // trailers of a request we answered already
            answered += e.streamId
            if (e.tooLarge) {
                try {
                    respond(e.streamId, listOf(":status" to "431"), endStream = true)
                } catch (_: IllegalStateException) {
                } catch (_: H2HeaderListTooLarge) {
                    core.reset(e.streamId, Http2ErrorCode.CANCEL, now)
                }
                core.release(e.streamId)
                return
            }
            val r =
                try {
                    H2Messages.parseRequest(e.fields, connectProtocolEnabled = mode.connect).also {
                        if (e.endStream && it.contentLength > 0 &&
                            it.method != "CONNECT"
                        ) {
                            throw MalformedMessage("content-length without content")
                        }
                    }
                } catch (_: MalformedMessage) {
                    // RFC 9113 section 8.1.1: a stream error of type PROTOCOL_ERROR, caused by the peer (as the engine does)
                    core.reset(e.streamId, Http2ErrorCode.PROTOCOL_ERROR, now, causedByPeer = true)
                    core.release(e.streamId)
                    reach?.hit("malformed request")
                    return
                }
            if (r.protocol != null) reach?.hit("Extended CONNECT accepted")
            handlers.start(e.streamId)
            if (mode.actions && bodySize and 64 != 0) trailers += e.streamId
            try {
                respond(e.streamId, listOf(":status" to "200"), endStream = false)
                bodyLeft[e.streamId] = bodySize
                pump(e.streamId)
            } catch (_: IllegalStateException) {
                // the stream was reset meanwhile: the driver's call is refused, and the handler, busy until it notices its
                // cancellation, returns a piece later
                handlers.cancel(e.streamId)
            } catch (_: H2HeaderListTooLarge) {
                // the peer's SETTINGS_MAX_HEADER_LIST_SIZE refuses even this response: an engine resets the stream
                core.reset(e.streamId, Http2ErrorCode.INTERNAL_ERROR, now)
                handlers.done(core, e.streamId)
            }
        }

        /** The driver's own action for a piece ending in [b]. */
        fun act(
            b: Int,
            now: Long,
        ) {
            when (b and 7) {
                1 -> {
                    core.ping(now)
                }

                2 -> {
                    core.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = true, now)
                }

                3 -> {
                    handlers.running.firstOrNull()?.let { core.reset(it, Http2ErrorCode.CANCEL, now) }
                }

                4 -> {
                    core.goAway(Http2ErrorCode.NO_ERROR, "bye".encodeToByteArray(), graceful = false, now)
                }

                5 -> {
                    handlers.running.lastOrNull()?.let { core.setPriority(it, (b shr 4) and 7, b and 0x80 != 0) }
                }

                else -> {}
            }
            drive(now, 1)
        }
    }
}

/**
 * Fuzz target `connectionClient`: input = [split byte][streams byte][mode byte ([Mode])][bytes from the server after its
 * SETTINGS]. A client core opens 1 + (streams byte % 8) requests (every third a POST with a body sent as the windows
 * allow), and an Extended CONNECT (RFC 8441, a WebSocket) once the server's SETTINGS allow it where the mode says, then
 * reads the input in pieces of 1 + (split byte) bytes, a tick of virtual time apart, driven like the engine: every field
 * section goes through the RFC 9113 section 8 checks (H2Messages; a malformed one resets its stream with PROTOCOL_ERROR
 * as an error of the peer's, a too large one with CANCEL), content is consumed, finished and reset streams are released,
 * timeouts fire when due, and the output is read as the mode says by a [WireMirror], which checks it against the
 * server's frames. Nothing may escape the core or the checks but their own errors; its state stays within its settings,
 * and the connection send window is conserved.
 */
class H2ClientConnectionFuzzTest {
    @BeforeEach fun nameTheCase(case: TestInfo) = fuzzCase(case)

    @FuzzTest(maxDuration = "60s")
    fun connectionClient(data: ByteArray) {
        if (data.size < 3) return
        val mode = Mode(data[2].toInt() and 0xff)
        val settings = mode.settings
        val core = H2ConnectionCore(Role.CLIENT, settings, 0)
        reach?.watch(core)
        val mirror = WireMirror(client = true, settings)
        var now = 0L
        // the server's preface (an empty SETTINGS frame) is not fuzzed: the core refuses anything else first (section 3.4)
        val preface = FrameEncoder.settings(IntArray(0), LongArray(0))
        mirror.peer(preface, 0, preface.size)
        core.receive(preface, 0, preface.size, now)
        val d = ClientDriver(core, mirror, mode)
        val streams = 1 + (data[1].toInt() and 0xff) % 8
        repeat(streams) { d.open(post = it % 3 == 2) }
        // a server answers what it read: our first flight (preface, SETTINGS, requests) goes first, unless the mode sends
        // the server's frames ahead of it, onto requests it has not seen (section 5.1: idle streams, a connection error)
        if (!mode.serverFirst) drain(core, mirror, now)
        val piece = 1 + (data[0].toInt() and 0xff)
        var p = 3
        var pieces = 0
        while (p < data.size && !core.isClosed) {
            val n = minOf(piece, data.size - p)
            now += mode.tick
            mirror.peer(data, p, n)
            core.receive(data, p, n, now)
            mirror.afterReceive(core.isClosed)
            p += n
            pieces++
            d.drive(now)
            if (mode.actions) d.act(data[p - 1].toInt() and 0xff, now)
            assertTrue(core.activeStreams <= d.opened, "streams ${core.activeStreams} of ${d.opened} opened")
            core.checkBounds()
            mode.drainAfter(pieces, core, mirror, now)
            core.nextTimeout()?.let { if (it <= now) core.onTimeout(now) }
        }
        d.drive(now)
        drain(core, mirror, now)
        mirror.atEnd(core.isClosed)
        reach?.let { r -> generateSequence { core.nextEvent() }.forEach { r.event(it) } }
    }

    private class ClientDriver(
        val core: H2ConnectionCore,
        val mirror: WireMirror,
        val mode: Mode,
    ) {
        var opened = 0
        private val bodyLeft = HashMap<Int, Int>()
        private val finalSeen = HashSet<Int>()
        private val live = LinkedHashSet<Int>()
        private var tunnel = -1
        private val body = ByteArray(16_384)

        private fun start(
            fields: List<Pair<String, String>>,
            endStream: Boolean,
        ): Int? {
            val id =
                try {
                    core.openStream(fields, endStream)
                } catch (_: H2StreamLimit) {
                    return null
                } catch (_: H2ConnectionUnusable) {
                    return null
                } catch (_: H2HeaderListTooLarge) {
                    return null
                }
            opened++
            live += id
            mirror.expect(id, fields)
            return id
        }

        fun open(post: Boolean) {
            val fields =
                listOf(
                    ":method" to (if (post) "POST" else "GET"),
                    ":scheme" to "https",
                    ":authority" to "example.com",
                    ":path" to "/$opened",
                )
            val id = start(fields, endStream = !post) ?: return
            if (post) {
                bodyLeft[id] = 100_000
                pump(id)
            }
        }

        /** RFC 8441 section 4: a WebSocket over a stream, once the server's SETTINGS_ENABLE_CONNECT_PROTOCOL allows it. */
        private fun openTunnel() {
            val fields =
                listOf(
                    ":method" to "CONNECT",
                    ":protocol" to "websocket",
                    ":scheme" to "https",
                    ":authority" to "example.com",
                    ":path" to "/chat",
                    "sec-websocket-version" to "13",
                )
            tunnel = start(fields, endStream = false) ?: return
            reach?.hit("Extended CONNECT opened")
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

        private fun done(id: Int) {
            live -= id
            core.release(id)
        }

        fun drive(now: Long) {
            while (true) {
                val e = core.nextEvent() ?: return
                reach?.event(e)
                when (e) {
                    is H2Event.HeadersReceived -> {
                        response(e, now)
                    }

                    is H2Event.Data -> {
                        core.consumed(e.streamId, e.data.size.toLong(), now)
                        if (e.endStream) done(e.streamId)
                    }

                    is H2Event.WindowAvailable -> {
                        pump(e.streamId)
                    }

                    is H2Event.StreamReset -> {
                        bodyLeft.remove(e.streamId)
                        done(e.streamId)
                    }

                    is H2Event.SettingsChanged -> {
                        if (mode.connect && tunnel < 0 && core.peerEnableConnectProtocol) openTunnel()
                    }

                    else -> {}
                }
            }
        }

        private fun response(
            e: H2Event.HeadersReceived,
            now: Long,
        ) {
            try {
                when {
                    e.tooLarge -> {
                        core.reset(e.streamId, Http2ErrorCode.CANCEL, now)
                    }

                    e.streamId in finalSeen -> {
                        H2Messages.parseTrailers(e.fields)
                    }

                    else -> {
                        val r = H2Messages.parseResponse(e.fields)
                        if (r.status >= 200) finalSeen += e.streamId
                        if (e.streamId == tunnel && r.status in 200..299) {
                            reach?.hit("Extended CONNECT established")
                            bodyLeft[tunnel] = 1_000 // the tunnel's first bytes
                            pump(tunnel)
                        }
                    }
                }
            } catch (_: MalformedMessage) {
                core.reset(e.streamId, Http2ErrorCode.PROTOCOL_ERROR, now, causedByPeer = true)
            }
            if (e.endStream) done(e.streamId)
        }

        fun act(
            b: Int,
            now: Long,
        ) {
            when (b and 7) {
                1 -> {
                    core.ping(now)
                }

                2 -> {
                    core.goAway(Http2ErrorCode.NO_ERROR, ByteArray(0), graceful = true, now)
                }

                3 -> {
                    live.firstOrNull()?.let { core.reset(it, Http2ErrorCode.CANCEL, now) }
                }

                4 -> {
                    live.lastOrNull()?.let { core.priorityUpdate(it, "u=${(b shr 4) and 7}", (b shr 4) and 7) }
                }

                5 -> {
                    open(post = b and 0x80 != 0)
                }

                6 -> {
                    live.firstOrNull()?.let { core.setPriority(it, (b shr 4) and 7, b and 0x80 != 0) }
                }

                else -> {}
            }
            drive(now)
        }
    }
}
