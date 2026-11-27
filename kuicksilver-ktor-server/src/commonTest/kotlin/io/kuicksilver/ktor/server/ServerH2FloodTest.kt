// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
)

package io.kuicksilver.ktor.server

import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.config.RateLimit
import io.kuicksilver.http2.http2Settings
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.updateAndGet
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/**
 * The HTTP/2 flood defences end to end, over TLS on a real loopback socket against the server engine (threat model 3.23;
 * RFC 9113 section 10.5): Rapid Reset (CVE-2023-44487), MadeYouReset (CVE-2025-8671), the CONTINUATION flood
 * (CVE-2023-45288, CVE-2024-27316), a client that floods without reading, a client that reads nothing of its responses,
 * and the backoff for an address whose connections keep ending in ENHANCE_YOUR_CALM. Handlers wait for cancellation (no
 * timers): the bound on running handlers is the engine's, not the test's pace. Whether the client still reads the
 * GOAWAY depends on the race between it and the TCP reset its unread frames cause at the close, so the server's own count
 * of connections it ended in a flood defence is what each test checks. A client that floods reads the server's SETTINGS
 * and acknowledges them first ([prefaceAcknowledged]): unacknowledged, they would end a flood that a slow host takes more
 * than 10 s over with SETTINGS_TIMEOUT before any flood limit.
 */
class ServerH2FloodTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val calm = 0xbL

    /** Handlers that run until cancelled, counted: [running] now, [maxRunning] at most. */
    private class Handlers {
        val running = MutableStateFlow(0)
        val maxRunning = MutableStateFlow(0)
        val started = MutableStateFlow(0L)

        suspend fun hold() {
            val n = running.updateAndGet { it + 1 }
            maxRunning.update { maxOf(it, n) }
            started.update { it + 1 }
            try {
                awaitCancellation()
            } finally {
                running.update { it - 1 }
            }
        }
    }

    private suspend fun floodServer(
        handlers: Handlers,
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
    ) = h2TlsServer(configure = configure) {
        routing {
            get("/hold") { handlers.hold() }
            get("/") { call.respondText("ok") }
            get("/big") { call.respondBytes(ByteArray(4 shl 20)) }
        }
    }

    /**
     * Writes the [count] frames [frame] makes, in batches of [batch], until the server stops taking them; returns how many
     * went out.
     *
     * Each batch is built by [batchOf], which does not suspend, and this loop makes no call whose target can change.
     * ART 7.0 (API 24) aborted in the GC here ("Tried to mark 0xebadde09 not contained by any spaces", a root in this
     * method's interpreted frame) when the batch was built inside the loop. The JIT-compiled loop was deoptimized (its call
     * of `frame` was compiled for the lambda it had seen, and the next test passes another), which fills every register the
     * compiled code had found dead with 0xEBADDE09 (kDeadValue). The coroutine state machine copies its locals between
     * registers with move-object at each resumption and loop turn, copies the compiler drops as dead; the interpreter that
     * went on from the deoptimization ran them, its move-object copies the raw register into the frame's references, and
     * the GC found 0xEBADDE09 there. Now the call that deoptimizes is in [batchOf], whose code has no such dead copies,
     * and this frame has nothing to deoptimize on.
     */
    private suspend fun RawH2Client.flood(
        count: Int,
        batch: Int = 500,
        frame: (Int) -> ByteArray,
    ): Int {
        var sent = 0
        while (sent < count) {
            val n = minOf(batch, count - sent)
            val all = batchOf(sent, n, frame)
            if (runCatching { write(all) }.isFailure) return sent
            sent += n
        }
        return sent
    }

    /**
     * [flood] one frame at a time, [pause] apart on the real clock, until [ended] (the server ended the connection): a
     * client slower than a timer of the server, which no event can stand for (tools/check/test-sleeps.allow).
     */
    private suspend fun RawH2Client.pacedFlood(
        count: Int,
        pause: Duration,
        ended: () -> Boolean,
        frame: (Int) -> ByteArray,
    ): Int {
        var sent = 0
        while (sent < count && !ended()) {
            val one = batchOf(sent, 1, frame)
            if (runCatching { write(one) }.isFailure) return sent
            sent++
            delay(pause)
        }
        return sent
    }

    /** The frames [frame] makes for [from] until [from] + [n], one after another. */
    private fun batchOf(
        from: Int,
        n: Int,
        frame: (Int) -> ByteArray,
    ): ByteArray {
        val bytes = ArrayList<ByteArray>(n)
        for (i in from until from + n) bytes += frame(i)
        val all = ByteArray(bytes.sumOf { it.size })
        var at = 0
        for (b in bytes) {
            b.copyInto(all, at)
            at += b.size
        }
        return all
    }

    /** Reads to the end of the connection and returns the GOAWAY the client saw, if any. */
    private suspend fun RawH2Client.goAwaySeen(): RawFrame? =
        runCatching { readToEnd(30.seconds) }.getOrNull()?.lastOrNull {
            it.type ==
                RawFrame.GOAWAY
        }

    private fun hold(id: Int) = RawH2Client.frame(RawFrame.HEADERS, 0x5, id, RawH2Client.block(RawH2Client.get("/hold")))

    /** Request [i] of a MadeYouReset flood: `/hold`, then a WINDOW_UPDATE of 0 on its stream (RFC 9113 section 6.9). */
    private fun madeYouReset(i: Int): ByteArray {
        val id = 1 + 2 * i
        return hold(id) + RawH2Client.frame(RawFrame.WINDOW_UPDATE, 0, id, byteArrayOf(0, 0, 0, 0))
    }

    /**
     * The client preface, then the server's SETTINGS read and acknowledged ([RawH2Client.readFrame]) before anything else
     * is written: a flood that reads nothing would leave them unacknowledged, and the connection would end with
     * SETTINGS_TIMEOUT (RFC 9113 section 6.5.3) after `settingsAckTimeout` (10 s) whenever the server takes longer than that
     * to reach a flood limit, as on a slow simulator, instead of with the flood defence the test is about.
     */
    private suspend fun RawH2Client.prefaceAcknowledged(vararg settings: Pair<Int, Long>) {
        preface(*settings)
        assertNotNull(await { it.type == RawFrame.SETTINGS && it.flags and 0x1 == 0 }, "the server's SETTINGS")
    }

    /**
     * The limits of the MadeYouReset tests: a glitch budget of 50 that never refills, and 10 concurrent streams. With the
     * defaults (10 000, 330 per second, 100 streams) a flood ends after anywhere from a few hundred requests (refused in a
     * row while the reset streams' handlers still run) to more than 10 000 (each accepted and reset, at a pace above the
     * refill), depending on how fast the handlers end: on a slow machine that takes longer than any deadline of the test.
     * Here at most 51 requests are accepted, whatever the pace.
     */
    private fun KuicksilverApplicationEngine.Configuration.smallGlitchBudget(settingsAckTimeout: Duration = 10.seconds) {
        http2 {
            settings {
                maxConcurrentStreams = MYR_STREAMS.toLong()
                this.settingsAckTimeout = settingsAckTimeout
                floodLimits { glitches = RateLimit(1, MYR_GLITCHES) }
            }
        }
        // a budget refills at 1 a second at least (RateLimit): the server's clock stands still (`h2ClockForTest`), so it
        // never refills however slow the host
        h2ClockForTest = { 0L }
    }

    /**
     * Rapid Reset (CVE-2023-44487): 10 000 requests each reset at once. Running handlers never pass
     * SETTINGS_MAX_CONCURRENT_STREAMS (a reset stream counts until its handler returns), the connection ends with
     * ENHANCE_YOUR_CALM once the reset budget (1000, 33 per second) is spent, and no handler is left afterwards. The
     * server's SETTINGS are acknowledged first ([prefaceAcknowledged]).
     */
    @Test fun negative_rapidResetDoesNotRunHandlersUnbounded() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers)
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.prefaceAcknowledged()
                    raw.flood(10_000) { i ->
                        val id = 1 + 2 * i
                        hold(id) + RawH2Client.frame(RawFrame.RST_STREAM, 0, id, byteArrayOf(0, 0, 0, 8))
                    }
                    raw.goAwaySeen()?.let { assertEquals(calm, it.errorCode) }
                }
                withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
                assertTrue(handlers.maxRunning.value <= 100, "handlers at once: ${handlers.maxRunning.value}")
                assertTrue(handlers.started.value < 2_000, "handlers started: ${handlers.started.value}")
                assertServes(port)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * MadeYouReset (CVE-2025-8671): requests the client makes the server reset itself (WINDOW_UPDATE of 0 on the open
     * stream, a stream error of the peer: RFC 9113 section 6.9), 20 000 of them written without reading. Our resets take
     * from the glitch budget ([smallGlitchBudget]), the handlers of reset streams count toward the concurrency limit, and
     * the connection ends with ENHANCE_YOUR_CALM, whichever limit the scheduler makes it reach first: the glitch budget
     * (each request accepted and reset) or the refusals in a row (handlers still running). The server's SETTINGS are
     * acknowledged first ([prefaceAcknowledged]), so no other limit can end it.
     */
    @Test fun negative_madeYouResetBounded() = madeYouResetFlood(20_000, pause = Duration.ZERO)

    /**
     * MadeYouReset as a slow machine runs it, the CI failure this guards against (iosSimulatorArm64): one request every
     * 30 ms, so the handlers mostly end in between and the requests are accepted and reset, and the flood takes longer
     * than the server's `settingsAckTimeout` (1 s here): about 1.5 s to the budget's 51st request, where the client stops
     * once the server counted the flood's end. Unacknowledged SETTINGS ended such a flood with SETTINGS_TIMEOUT (0x4)
     * before any flood limit; acknowledged ([prefaceAcknowledged]), it ends with ENHANCE_YOUR_CALM at the glitch budget.
     */
    @Test fun negative_madeYouResetSlowerThanTheSettingsTimeoutEndsCalm() =
        madeYouResetFlood(4 * MYR_GLITCHES, pause = 30.milliseconds, settingsAckTimeout = 1.seconds)

    /** [count] MadeYouReset requests written without reading, all at once or one every [pause] (the tests above). */
    private fun madeYouResetFlood(
        count: Int,
        pause: Duration,
        settingsAckTimeout: Duration = 10.seconds,
    ) = serverTest {
        val handlers = Handlers()
        val (server, port) = floodServer(handlers) { smallGlitchBudget(settingsAckTimeout) }
        try {
            RawH2Client.connect(port).use { raw ->
                raw.prefaceAcknowledged()
                val sent =
                    if (pause.isPositive()) {
                        raw.pacedFlood(count, pause, { server.engine.h2FloodEnds.value > 0 }, ::madeYouReset)
                    } else {
                        raw.flood(count, frame = ::madeYouReset)
                    }
                raw.goAwaySeen()?.let { assertEquals(calm, it.errorCode, "GOAWAY after $sent requests") }
            }
            withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
            withTimeout(10.seconds) { handlers.running.first { it == 0 } }
            assertTrue(handlers.maxRunning.value <= MYR_STREAMS, "handlers at once: ${handlers.maxRunning.value}")
            assertTrue(handlers.started.value <= MYR_GLITCHES + 1, "handlers started: ${handlers.started.value}")
            assertServes(port)
        } finally {
            server.stop(100, 500)
        }
    }

    /**
     * MadeYouReset one request at a time: each WINDOW_UPDATE of 0 is answered with RST_STREAM(PROTOCOL_ERROR) before the
     * next request goes out, so the server's reset count does not depend on how it batches its reads or on how fast
     * handlers end. Each of our resets is a glitch: the 50 of the budget are answered with RST_STREAM (the client's preface
     * SETTINGS takes none), and the request that would take one more is answered with GOAWAY(ENHANCE_YOUR_CALM) instead,
     * never later. The client writes only after an answer and after the core freed the stream, so nothing it sends can
     * arrive after the server closed and no request is refused (REFUSED_STREAM, while a reset stream's handler still
     * holds it, is not the client's error and would take nothing from the budget).
     */
    @Test fun negative_madeYouResetSpendsTheGlitchBudget() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers) { smallGlitchBudget() }
            try {
                val r = RawH2Client.connect(port).use { raw -> raw.madeYouResetInStep(server, handlers, window = 1, max = 2_000) }
                assertEquals(calm, r.goAway.errorCode, "$r")
                assertEquals(0, r.refused, "no request refused between rounds: $r")
                assertEquals(MYR_GLITCHES, r.resets, "the whole budget, the client's preface SETTINGS takes none: $r")
                withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
                assertTrue(handlers.maxRunning.value <= MYR_STREAMS, "handlers at once: ${handlers.maxRunning.value}")
                assertServes(port)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * MadeYouReset in step with the default limits (glitch budget 10 000, 100 streams), so they stay covered end to end:
     * rounds of 50 requests, each round's answers read and its streams freed by the core before the next, so no request is
     * refused for streams our handlers still hold and none takes from the budget but by its reset. The server's clock stands still
     * (`h2ClockForTest`), so the budget's refill (330 per second) gives nothing however slow the host: the connection ends
     * with ENHANCE_YOUR_CALM after exactly the burst of resets.
     */
    @Test fun negative_madeYouResetSpendsTheDefaultGlitchBudget() =
        serverTest {
            val handlers = Handlers()
            val defaults = io.kuicksilver.http2.Http2Settings.Default
            val (server, port) = floodServer(handlers) { h2ClockForTest = { 0L } }
            try {
                val r = RawH2Client.connect(port).use { raw -> raw.madeYouResetInStep(server, handlers, window = 50, max = 20_000) }
                assertEquals(calm, r.goAway.errorCode, "$r")
                assertEquals(0, r.refused, "no request refused between rounds: $r")
                assertEquals(defaults.glitchBurst, r.resets, "the whole burst, no refill: $r")
                withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
                assertTrue(handlers.maxRunning.value <= defaults.maxConcurrentStreams, "handlers at once: ${handlers.maxRunning.value}")
                assertServes(port)
            } finally {
                server.stop(100, 500)
            }
        }

    /** What [madeYouResetInStep] saw: our resets for the client's error, refusals, and the GOAWAY that ended it. */
    private data class InStep(
        val resets: Int,
        val refused: Int,
        val requests: Int,
        val goAway: RawFrame,
    ) {
        override fun toString() = "$resets resets and $refused refusals of $requests requests, GOAWAY ${goAway.errorCode}"
    }

    /**
     * MadeYouReset requests in rounds of [window], at most [max]: each round's answers (RST_STREAM for each of its streams)
     * are read, its handlers ended and its streams freed by the core of [server]'s connection (`openRequests` back at 0: a
     * handler that returned has not released its stream yet, and a request that comes before would be refused), before
     * the next round goes out, until the server's GOAWAY; the client then has nothing in flight that could arrive after the
     * server closed. The server's SETTINGS are acknowledged first.
     */
    private suspend fun RawH2Client.madeYouResetInStep(
        server: Server,
        handlers: Handlers,
        window: Int,
        max: Int,
    ): InStep {
        prefaceAcknowledged()
        var resets = 0
        var refused = 0
        var sent = 0
        while (sent < max) {
            val first = sent
            write(batchOf(first, window, ::madeYouReset))
            sent += window
            val waiting = HashSet<Int>()
            for (i in first until sent) waiting += 1 + 2 * i
            while (waiting.isNotEmpty()) {
                val f =
                    assertNotNull(
                        await { it.type == RawFrame.GOAWAY || (it.type == RawFrame.RST_STREAM && it.stream in waiting) },
                        "no answer to streams $waiting after $resets resets and $refused refusals",
                    )
                if (f.type == RawFrame.GOAWAY) return InStep(resets, refused, sent, f)
                waiting -= f.stream
                when (f.errorCode) {
                    0x1L -> resets++
                    0x7L -> refused++
                    else -> error("stream ${f.stream} reset with ${f.errorCode}")
                }
            }
            withTimeout(10.seconds) { handlers.running.first { it == 0 } }
            withTimeout(10.seconds) { liveConnection(server).openRequests.first { it == 0 } }
        }
        error("no GOAWAY after $resets resets and $refused refusals of $sent requests")
    }

    /**
     * The CONTINUATION flood (CVE-2023-45288, CVE-2024-27316): a field block that never ends. The connection ends after
     * 8 CONTINUATION frames (the core never buffers more than twice SETTINGS_MAX_HEADER_LIST_SIZE: core.FloodTest), its
     * HTTP/2 layer stops reading there (at most one read buffer past the ninth frame), and the socket is released after
     * the short close bound of a connection that ended in an error, although the client keeps its end open and the buffers
     * in front of the server's socket full. Asserted on the server's side: how many of the client's
     * million frames its writes got rid of depends on the socket buffers between the two (on Android they take all of
     * them), not on the server.
     */
    @Test fun negative_continuationFloodBounded() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers)
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.prefaceAcknowledged()
                    raw.write(RawH2Client.frame(RawFrame.HEADERS, 0x1, 1, RawH2Client.block(RawH2Client.get("/hold"))))
                    raw.flood(1_000_000, batch = 10_000) { RawH2Client.frame(RawFrame.CONTINUATION, 0, 1, byteArrayOf(0)) }
                    withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                    // released while the client still holds its end and keeps its frames unread: after the short close
                    // bound of a connection that ended in an error (3 s without progress), not the send-stall time
                    withTimeout(15.seconds) { server.engine.openTcpSockets.first { it == 0 } }
                    raw.goAwaySeen()?.let { assertEquals(calm, it.errorCode) }
                }
                val read = server.engine.h2BytesRead.value
                assertTrue(read < 64 * 1024, "the HTTP/2 layer read $read bytes of a 10 MB flood")
                assertEquals(0L, handlers.started.value, "no request reached a handler")
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The flood classes that make the server answer, or cost it a frame's work, sent without reading anything back:
     * SETTINGS (CVE-2019-9515), PRIORITY shuffling (CVE-2019-9513), frames of an unknown type, empty DATA on an open request
     * (CVE-2019-9518) and requests with a zero-length field block (CVE-2019-9516's empty headers: malformed, RFC 9113
     * section 8.1.1, each reset as the client's error, CVE-2019-9514). Each ends with ENHANCE_YOUR_CALM (the glitch
     * budget, the empty-frame limit or the bound on queued control frames: core.FloodClassesTest measures each), no request
     * reaches a handler beyond the one held open, and the server keeps serving.
     */
    @Test fun negative_floodClassesWithoutReadingEndCalm() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers)
            val floods: List<Pair<String, (Int) -> ByteArray>> =
                listOf(
                    "SETTINGS" to { i -> RawH2Client.frame(RawFrame.SETTINGS, 0, 0, byteArrayOf(0, 4, 0, 0, 0, (1 + (i and 1)).toByte())) },
                    "PRIORITY" to { i ->
                        RawH2Client.frame(
                            RawFrame.PRIORITY,
                            0,
                            1 + 2 * (i % 100),
                            byteArrayOf(0, 0, 0, (1 + 2 * ((i + 1) % 100)).toByte(), 15),
                        )
                    },
                    "unknown type" to { _ -> RawH2Client.frame(0xfa, 0, 0, ByteArray(0)) },
                    "empty DATA" to
                        { i ->
                            if (i ==
                                0
                            ) {
                                RawH2Client.frame(RawFrame.HEADERS, 0x4, 1, RawH2Client.block(RawH2Client.get("/hold")))
                            } else {
                                RawH2Client.frame(RawFrame.DATA, 0, 1, ByteArray(0))
                            }
                        },
                    "zero-length HEADERS" to { i -> RawH2Client.frame(RawFrame.HEADERS, 0x5, 1 + 2 * i, ByteArray(0)) },
                )
            try {
                for ((k, flood) in floods.withIndex()) {
                    RawH2Client.connect(port).use { raw ->
                        raw.prefaceAcknowledged()
                        raw.flood(100_000, batch = 1_000, frame = flood.second)
                        withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == k + 1L } }
                    }
                    withTimeout(10.seconds) { handlers.running.first { it == 0 } }
                }
                assertTrue(handlers.started.value <= 1, "handlers started: ${handlers.started.value}")
                assertServes(port)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * WINDOW_UPDATE floods (RFC 9113 section 10.5: "Providing tiny increments to flow control"): 100 000 increments of one
     * byte with no DATA of ours in between are glitches and end with ENHANCE_YOUR_CALM, a flood strike; increments of
     * 64 KiB are bounded by the window and end with FLOW_CONTROL_ERROR above 2^31 - 1 (section 6.9.1), no strike. Neither
     * is answered or builds state (core.FloodClassesTest).
     */
    @Test fun negative_windowUpdateFloodsEnd() =
        serverTest {
            val (server, port) = floodServer(Handlers())
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.prefaceAcknowledged()
                    raw.flood(100_000, batch = 1_000) { RawH2Client.frame(RawFrame.WINDOW_UPDATE, 0, 0, byteArrayOf(0, 0, 0, 1)) }
                    withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                }
                RawH2Client.connect(port).use { raw ->
                    raw.prefaceAcknowledged()
                    raw.flood(40_000, batch = 1_000) { RawH2Client.frame(RawFrame.WINDOW_UPDATE, 0, 0, byteArrayOf(0, 1, 0, 0)) }
                    raw.goAwaySeen()?.let { assertEquals(0x3L, it.errorCode) }
                }
                assertServes(port)
                assertEquals(1L, server.engine.h2FloodEnds.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /** A server whose `/big` responses (4 MiB) count their handlers' ends in [ended]. */
    private suspend fun bigServer(
        ended: MutableStateFlow<Int>,
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit,
    ) = h2TlsServer(configure = configure) {
        routing {
            get("/big") {
                try {
                    call.respondBytes(ByteArray(4 shl 20))
                } finally {
                    ended.update { it + 1 }
                }
            }
        }
    }

    /**
     * Slow read: a client that requests large responses and reads nothing (flow control wide open, so only the socket
     * holds them back). The core holds at most one DATA frame per stream, and every handler ends after the send-stall
     * deadline (its stream reset), so neither memory nor handlers are pinned by the client.
     */
    @Test fun negative_slowReadDoesNotPinResponses() =
        serverTest {
            val ended = MutableStateFlow(0)
            val (server, port) = bigServer(ended) { sendStallTimeoutForTest = 2.seconds }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.wideOpenPreface()
                    for (i in 0 until 20) raw.headers(1 + 2 * i, RawH2Client.get("/big"))
                    // nothing read: every handler ends within the stall deadline, not when the client goes
                    withTimeout(30.seconds) { ended.first { it == 20 } }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A client that reads nothing, then floods PINGs once the socket is full (its large responses stalled): the answers
     * fill the control queue (10 000), the connection ends with ENHANCE_YOUR_CALM, and what is left to write cannot go
     * out. The connection is cut off after the send-stall deadline, not held until the idle timeout.
     */
    @Test fun negative_floodWithoutReadingIsCutOffAfterTheStallDeadline() =
        serverTest {
            val ended = MutableStateFlow(0)
            val (server, port) =
                bigServer(ended) {
                    sendStallTimeoutForTest = 2.seconds
                    tcp { idleTimeout = 600.seconds }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.wideOpenPreface()
                    for (i in 0 until 4) raw.headers(1 + 2 * i, RawH2Client.get("/big"))
                    withTimeout(30.seconds) { ended.first { it == 4 } } // the responses stalled: the socket is full
                    raw.flood(30_000, batch = 1_000) { RawH2Client.frame(RawFrame.PING, 0, 0, ByteArray(8)) }
                    withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                    // still not reading: the server lets go of the socket on its own
                    withTimeout(20.seconds) { server.engine.openTcpSockets.first { it == 0 } }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** Three CONTINUATION floods from this address, each ended by the server. */
    private suspend fun threeFloods(
        server: Server,
        port: Int,
    ) {
        val before = server.engine.h2FloodEnds.value
        for (k in 1..3) {
            RawH2Client.connect(port).use { raw ->
                raw.preface()
                raw.write(RawH2Client.frame(RawFrame.HEADERS, 0x1, 1, RawH2Client.block(RawH2Client.get())))
                raw.flood(100) { RawH2Client.frame(RawFrame.CONTINUATION, 0, 1, byteArrayOf(0)) }
                raw.goAwaySeen()
            }
            withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == before + k } }
        }
    }

    /**
     * With `http2 { repeatOffenderPenalty }`, an address whose HTTP/2 connections end in ENHANCE_YOUR_CALM three times within a
     * minute is refused at accept (before TLS) for the penalty; then it is served again.
     */
    @Test fun negative_repeatOffenderBackoff() =
        serverTest {
            val handlers = Handlers()
            val refusals = MutableStateFlow<List<String>>(emptyList())
            val listener =
                object : KuicksilverServerEventListener() {
                    override fun connectionRefused(
                        protocol: io.ktor.http.HttpProtocolVersion,
                        remote: io.ktor.network.sockets.InetSocketAddress?,
                        reason: String,
                    ) = refusals.update { it + "$protocol $reason" }
                }
            val (server, port) =
                floodServer(handlers) {
                    http2 { repeatOffenderPenalty = 30.seconds }
                    observability { eventListener = listener }
                }
            val clock = TestTimeSource()
            assertNotNull(server.engine.h2Offenders, "on with a positive penalty")
            server.engine.h2Offenders = RepeatOffenders(penalty = 30.seconds, timeSource = clock)
            try {
                threeFloods(server, port)
                assertFailsWith<Throwable>("refused before the TLS handshake") { RawH2Client.connect(port).close() }
                withTimeout(10.seconds) { server.engine.refusedOffenders.first { it == 1L } }
                assertEquals(listOf("HTTP/1.1 HTTP/2 repeat offender"), refusals.value, "reported to connectionRefused")
                clock += 30.seconds
                assertServes(port)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * On a PROXY protocol connector the TCP peer is the proxy that carries every client. Three floods behind headers that
     * name no client (`PROXY UNKNOWN`) must strike nobody: struck by the proxy's address, they would refuse the proxy, and
     * so a client whose header names it (`TCP4`) behind the same proxy, at accept.
     */
    @Test fun negative_floodsBehindAnUnknownProxyHeaderDoNotRefuseTheProxy() =
        serverTest {
            val (server, port) =
                h2TlsServer(
                    configure = { http2 { repeatOffenderPenalty = 30.seconds } },
                    connector = { proxyProtocol { trust("127.0.0.1") } },
                ) {
                    routing { get("/") { call.respondText("ok") } }
                }
            val unknown = "PROXY UNKNOWN\r\n".encodeToByteArray()
            try {
                val before = server.engine.h2FloodEnds.value
                for (k in 1..3) {
                    RawH2Client.connect(port, proxyPrefix = unknown).use { raw ->
                        raw.preface()
                        raw.write(RawH2Client.frame(RawFrame.HEADERS, 0x1, 1, RawH2Client.block(RawH2Client.get())))
                        raw.flood(100) { RawH2Client.frame(RawFrame.CONTINUATION, 0, 1, byteArrayOf(0)) }
                        raw.goAwaySeen()
                    }
                    withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == before + k } }
                }
                // the proxy's own address was not struck either (the accept-time check is skipped on such a connector, so
                // only the table tells)
                assertEquals(false, server.engine.h2Offenders!!.refuses(parseIpLiteral("127.0.0.1")), "the proxy was struck")
                val client = "PROXY TCP4 192.0.2.67 198.51.100.2 40000 443\r\n".encodeToByteArray()
                RawH2Client.connect(port, proxyPrefix = client).use { raw ->
                    raw.preface()
                    raw.headers(1, RawH2Client.get())
                    val f = assertNotNull(raw.await(within = 15.seconds) { (it.stream == 1 && it.endStream) || it.type == RawFrame.GOAWAY })
                    assertEquals(1, f.stream, "a client behind the proxy is served after floods behind UNKNOWN headers: $f")
                }
                assertEquals(0L, server.engine.refusedOffenders.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Off by default: every client behind one shared address (a NAT, an L4 load balancer that rewrites source addresses)
     * would be refused with a flooder, so only the per-connection limits apply unless the operator turns it on.
     */
    @Test fun repeatOffenderBackoffIsOffByDefault() =
        serverTest {
            val (server, port) = floodServer(Handlers())
            try {
                assertNull(server.engine.h2Offenders)
                threeFloods(server, port)
                assertServes(port)
                assertEquals(0L, server.engine.refusedOffenders.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A field block slower than its deadline ends its connection (ENHANCE_YOUR_CALM) but is no flood strike.
     *
     * The deadline is the core's `maxHeaderBlockTime`, not a 1 s `requestHeaderTimeout`: that also bounds the TLS
     * handshake and the connection preface from the accepted connection on, and on a loaded host (a Windows VM) the two took
     * longer than 1 s, so the server answered the late preface with GOAWAY NO_ERROR ("expected: <11> but was: <0>"), as
     * negative_prefaceSlowerThanTimeoutCloses asserts, before any field block began.
     */
    @Test fun slowFieldBlockIsNotAFloodStrike() =
        serverTest {
            val (server, port) =
                floodServer(Handlers()) {
                    http2 {
                        settings { maxHeaderBlockTime = 1.seconds }
                        repeatOffenderPenalty = 30.seconds
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    // the server's SETTINGS acknowledged first: our acknowledgement inside the field block would be a
                    // PROTOCOL_ERROR of its own
                    assertNotNull(raw.await { it.type == RawFrame.SETTINGS && it.flags and 1 == 0 })
                    raw.write(RawH2Client.frame(RawFrame.HEADERS, 0x1, 1, RawH2Client.block(RawH2Client.get())))
                    raw.goAwaySeen()?.let { assertEquals(calm, it.errorCode) }
                }
                withTimeout(15.seconds) { server.engine.openTcpSockets.first { it == 0 } }
                assertEquals(0L, server.engine.h2FloodEnds.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Sustained cancellations below the refill rate: 25 a second for 60 seconds of the connections' clock (a test clock,
     * moved a second per round), 1500 in all, past the burst of 1000; the reset budget refills at 33 a second, so the
     * connection goes on.
     */
    @Test fun sustainedCancellationsBelowTheRefillRateAreNotPunished() =
        serverTest {
            val now = kotlin.concurrent.atomics.AtomicLong(0L)
            val (server, port) =
                floodServer(Handlers()) { h2ClockForTest = { now.load() } }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    assertNotNull(raw.await { it.type == RawFrame.SETTINGS && it.flags and 1 == 0 }) // acknowledged on read
                    val c =
                        liveConnection(server)
                    var next = 1
                    for (second in 1..60) {
                        raw.flood(25, batch = 25) {
                            val id = next
                            next += 2
                            hold(id) + RawH2Client.frame(RawFrame.RST_STREAM, 0, id, byteArrayOf(0, 0, 0, 8))
                        }
                        withTimeout(10.seconds) { c.requestsTaken.first { it == 25L * second } }
                        withTimeout(10.seconds) { c.openRequests.first { it == 0 } }
                        now.addAndFetch(1_000_000_000L)
                    }
                    raw.headers(next, RawH2Client.get())
                    val end = assertNotNull(raw.await(within = 15.seconds) { it.stream == next || it.type == RawFrame.GOAWAY })
                    assertEquals(next, end.stream, "the connection went on: $end")
                }
                assertEquals(0L, server.engine.h2FloodEnds.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Browsers cancel requests as a page is left (RFC 9113 section 8.7 makes that RST_STREAM CANCEL): 300 cancellations on
     * one connection, in rounds of 30 as navigations come, stay within the reset budget; the connection goes on and nothing
     * counts against the address.
     */
    @Test fun legitimateBrowserCancellationsNotPunished() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers)
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.prefaceAcknowledged()
                    var next = 1
                    for (round in 1..10) {
                        raw.flood(30, batch = 30) {
                            val id = next
                            next += 2
                            hold(id) + RawH2Client.frame(RawFrame.RST_STREAM, 0, id, byteArrayOf(0, 0, 0, 8))
                        }
                        // the round's requests arrived and their handlers were released (a reset stream counts toward
                        // SETTINGS_MAX_CONCURRENT_STREAMS until then, so a burst beyond 100 would be refused)
                        val c =
                            liveConnection(server)
                        withTimeout(10.seconds) { c.requestsTaken.first { it == 30L * round } }
                        withTimeout(10.seconds) { c.openRequests.first { it == 0 } }
                    }
                    raw.headers(next, RawH2Client.get())
                    val frames = ArrayList<RawFrame>()
                    val end =
                        assertNotNull(
                            raw.await(within = 15.seconds) {
                                frames += it
                                (it.stream == next && it.endStream) || it.type == RawFrame.GOAWAY || it.type == RawFrame.RST_STREAM
                            },
                        )
                    assertTrue(end.stream == next && end.type != RawFrame.RST_STREAM, "the connection went on: ${frames.takeLast(5)}")
                }
                assertEquals(0L, server.engine.h2FloodEnds.value)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The preface with the largest stream window (SETTINGS_INITIAL_WINDOW_SIZE) and connection window flow control allows,
     * the server's SETTINGS acknowledged ([prefaceAcknowledged]).
     */
    private suspend fun RawH2Client.wideOpenPreface() {
        prefaceAcknowledged(0x4 to 0x7fff_ffffL)
        write(RawH2Client.frame(RawFrame.WINDOW_UPDATE, 0, 0, byteArrayOf(0x7f, 0xff.toByte(), 0, 0)))
    }

    /** The server's one HTTP/2 connection, once the engine registered it (after its runtime started). */
    private suspend fun liveConnection(server: Server): io.kuicksilver.http2.runtime.H2ServerConnection {
        withTimeout(10.seconds) {
            server.engine.h2Live.count
                .first { it == 1 }
        }
        return server.engine.h2Live
            .live()
            .single()
    }

    /** The server still serves a new connection from the same address. */
    private suspend fun assertServes(port: Int) {
        RawH2Client.connect(port).use { raw ->
            raw.preface()
            raw.headers(1, RawH2Client.get())
            val f = assertNotNull(raw.await(within = 15.seconds) { (it.stream == 1 && it.endStream) || it.type == RawFrame.GOAWAY })
            assertEquals(1, f.stream, "$f")
        }
    }

    private companion object {
        /** SETTINGS_MAX_CONCURRENT_STREAMS of [smallGlitchBudget]. */
        const val MYR_STREAMS = 10

        /** The glitch budget of [smallGlitchBudget]. */
        const val MYR_GLITCHES = 50
    }
}
