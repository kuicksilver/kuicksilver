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
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.awaitCancellation
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
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/**
 * The HTTP/2 flood defences end to end, over TLS on a real loopback socket against the server engine (threat model 3.23;
 * RFC 9113 section 10.5): Rapid Reset (CVE-2023-44487), MadeYouReset (CVE-2025-8671), the CONTINUATION flood
 * (CVE-2023-45288, CVE-2024-27316), a client that floods without reading, a client that reads nothing of its responses,
 * and the backoff for an address whose connections keep ending in ENHANCE_YOUR_CALM. Handlers wait for cancellation (no
 * timers): the bound on running handlers is the engine's, not the test's pace. Whether the client still reads the
 * GOAWAY depends on the race between it and the TCP reset its unread frames cause at the close, so the server's own count
 * of connections it ended in a flood defence is what each test checks.
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

    /** Writes [frames] in batches of [batch] until the server stops taking them; returns how many went out. */
    private suspend fun RawH2Client.flood(
        count: Int,
        batch: Int = 500,
        frame: (Int) -> ByteArray,
    ): Int {
        var sent = 0
        while (sent < count) {
            val n = minOf(batch, count - sent)
            val bytes = ArrayList<ByteArray>(n)
            for (i in sent until sent + n) bytes += frame(i)
            val all = ByteArray(bytes.sumOf { it.size })
            var at = 0
            for (b in bytes) {
                b.copyInto(all, at)
                at += b.size
            }
            if (runCatching { write(all) }.isFailure) return sent
            sent += n
        }
        return sent
    }

    /** Reads to the end of the connection and returns the GOAWAY the client saw, if any. */
    private suspend fun RawH2Client.goAwaySeen(): RawFrame? =
        runCatching { readToEnd(30.seconds) }.getOrNull()?.lastOrNull {
            it.type ==
                RawFrame.GOAWAY
        }

    private fun hold(id: Int) = RawH2Client.frame(RawFrame.HEADERS, 0x5, id, RawH2Client.block(RawH2Client.get("/hold")))

    /**
     * Rapid Reset (CVE-2023-44487): 10 000 requests each reset at once. Running handlers never pass
     * SETTINGS_MAX_CONCURRENT_STREAMS (a reset stream counts until its handler returns), the connection ends with
     * ENHANCE_YOUR_CALM once the reset budget (1000, 33 per second) is spent, and no handler is left afterwards.
     */
    @Test fun negative_rapidResetDoesNotRunHandlersUnbounded() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers)
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
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
     * stream, a stream error of ours). Our resets take from the glitch budget, the handlers of reset streams count toward
     * the concurrency limit, and the connection ends with ENHANCE_YOUR_CALM.
     */
    @Test fun negative_madeYouResetBounded() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers)
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.flood(20_000) { i ->
                        val id = 1 + 2 * i
                        hold(id) + RawH2Client.frame(RawFrame.WINDOW_UPDATE, 0, id, byteArrayOf(0, 0, 0, 0))
                    }
                    raw.goAwaySeen()?.let { assertEquals(calm, it.errorCode) }
                }
                withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                withTimeout(10.seconds) { handlers.running.first { it == 0 } }
                assertTrue(handlers.maxRunning.value <= 100, "handlers at once: ${handlers.maxRunning.value}")
                assertServes(port)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The CONTINUATION flood (CVE-2023-45288, CVE-2024-27316): a field block that never ends. The connection ends after
     * 8 CONTINUATION frames (the core never buffers more than twice SETTINGS_MAX_HEADER_LIST_SIZE: core.FloodTest), long
     * before the client could write a million of them: the server stops reading.
     */
    @Test fun negative_continuationFloodBounded() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers)
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    raw.write(RawH2Client.frame(RawFrame.HEADERS, 0x1, 1, RawH2Client.block(RawH2Client.get("/hold"))))
                    val sent = raw.flood(1_000_000, batch = 10_000) { RawH2Client.frame(RawFrame.CONTINUATION, 0, 1, byteArrayOf(0)) }
                    assertTrue(sent < 1_000_000, "the server took all of a million CONTINUATION frames")
                    raw.goAwaySeen()?.let { assertEquals(calm, it.errorCode) }
                }
                withTimeout(10.seconds) { server.engine.h2FloodEnds.first { it == 1L } }
                assertEquals(0L, handlers.started.value, "no request reached a handler")
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
                    connectionIdleTimeoutSeconds = 600
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
     * With `http2RepeatOffenderPenalty`, an address whose HTTP/2 connections end in ENHANCE_YOUR_CALM three times within a
     * minute is refused at accept (before TLS) for the penalty; then it is served again.
     */
    @Test fun negative_repeatOffenderBackoff() =
        serverTest {
            val handlers = Handlers()
            val (server, port) = floodServer(handlers) { http2RepeatOffenderPenalty = 30.seconds }
            val clock = TestTimeSource()
            assertNotNull(server.engine.h2Offenders, "on with a positive penalty")
            server.engine.h2Offenders = RepeatOffenders(penalty = 30.seconds, timeSource = clock)
            try {
                threeFloods(server, port)
                assertFailsWith<Throwable>("refused before the TLS handshake") { RawH2Client.connect(port).close() }
                assertEquals(1L, server.engine.refusedOffenders.value)
                clock += 30.seconds
                assertServes(port)
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

    /** A field block slower than the request-head deadline ends its connection (ENHANCE_YOUR_CALM) but is no flood strike. */
    @Test fun slowFieldBlockIsNotAFloodStrike() =
        serverTest {
            val (server, port) =
                floodServer(Handlers()) {
                    requestHeaderTimeoutSeconds = 1
                    http2RepeatOffenderPenalty = 30.seconds
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
                        withTimeout(10.seconds) {
                            server.engine.h2Live
                                .live()
                                .single()
                        }
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
                    raw.preface()
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
                            withTimeout(10.seconds) {
                                server.engine.h2Live
                                    .live()
                                    .single()
                            }
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

    /** The preface with the largest stream window (SETTINGS_INITIAL_WINDOW_SIZE) and connection window flow control allows. */
    private suspend fun RawH2Client.wideOpenPreface() {
        preface(0x4 to 0x7fff_ffffL)
        write(RawH2Client.frame(RawFrame.WINDOW_UPDATE, 0, 0, byteArrayOf(0x7f, 0xff.toByte(), 0, 0)))
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
}
