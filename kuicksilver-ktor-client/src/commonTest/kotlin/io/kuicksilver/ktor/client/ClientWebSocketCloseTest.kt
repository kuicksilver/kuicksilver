// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.EOFException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * How a client WebSocket session over HTTP/1.1 ends when its call ends with a cancellation right after the session queued
 * its own Close, as every session of Ktor's `HttpClient.webSocketSession()` does (its builder takes the cancelled
 * outgoing channel for a failure and cancels the call): the Close still goes out (RFC 6455 section 7.1.2, an endpoint
 * that starts the closing handshake "MUST send a Close control frame").
 */
class ClientWebSocketCloseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * The client's writer is held at the socket behind a large frame (the server reads nothing yet) when the session
     * queues its Close and Ktor's builder cancels the call: once the server reads, it gets the frame and then the Close
     * with the application's code and reason. Before, the call's cancellation cancelled the writer with it, and the
     * connection ended without a Close.
     */
    @Test fun closeQueuedBeforeTheCallIsCancelledIsWritten() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val reading = CompletableDeferred<Unit>()
            try {
                coroutineScope {
                    val served =
                        async {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                val output = s.openWriteChannel(autoFlush = true)
                                output.writeStringUtf8(switchingProtocols(input.readWebSocketKey()))
                                reading.await() // nothing is read before the client's call is over
                                readClientFrames(input)
                            }
                        }
                    testClient(block = { install(WebSockets) }).use { c ->
                        (c.engine as KuicksilverEngine).h1.webSocketCloseWaitMillis = 60_000
                        val port = (listener.localAddress as InetSocketAddress).port
                        val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                        session.outgoing.send(Frame.Binary(true, ByteArray(BIG)))
                        // close() also waits for the writer: in the background
                        launch { session.close(CloseReason(4002, "client bye")) }
                        // Ktor's builder ends the call as soon as the session's Close is queued, with a cancellation
                        session.call.coroutineContext[Job]!!.join()
                        reading.complete(Unit)
                        assertEquals(listOf("binary $BIG", "close 4002 client bye"), withTimeout(20.seconds) { served.await() })
                    }
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * `close(reason)` and then `client.close()` at once, the writer still held behind a large frame that the server starts
     * to read right after: the engine's cleanup (its pools, its selector) waits for the session to write its Close and
     * end, instead of closing the connection under it. Before, the cleanup ran as soon as the call ended and the
     * handed-over socket stayed open past it, unaccounted.
     */
    @Test fun clientCloseWaitsForTheSessionsClose() = clientCloseWithAHeldWriter()

    /**
     * The same against a server that takes nothing (its receive window full, the client's send buffer full): the session
     * has not written its Close, so the engine's close does not cut it short; it keeps its close wait (T1, 1 s here), and
     * only then is it cut and the connection reset. The cleanup waits for that, not longer. Its Close never left: the
     * server took none of the stream. That the Close cannot be written needs more data ahead of it than the buffers
     * take, which the system sizes: [unwrittenCloseAttempts] sends more frames until it is ([zeroReaderAttempt]).
     */
    @Test fun negative_clientCloseLeavesAWriterTheServerTakesNothingFromItsCloseWait() =
        clientTest(UNWRITTEN_CLOSE_TEST_TIMEOUT) {
            unwrittenCloseAttempts { data, frames -> zeroReaderAttempt(data, frames, closeWait = 1_000) }
        }

    /**
     * The same with `client.close()` late in T1 (1.5 s into a 2 s close wait): the session still ends at its T1, counted
     * from its own Close, and the connection reset; the engine's close starts no close wait of its own.
     */
    @Test fun negative_aLateClientCloseEndsAWriterTheServerTakesNothingFromAtItsT1() =
        clientTest(UNWRITTEN_CLOSE_TEST_TIMEOUT) {
            unwrittenCloseAttempts { data, frames ->
                zeroReaderAttempt(data, frames, closeWait = 2_000, closeAt = 1_500.milliseconds)
            }
        }

    /**
     * The session's Close waits in the socket's channel, in front of a kernel that takes nothing more (the server reads
     * nothing), when the engine is closed: it has not been written, so the session keeps its close wait (T1, 3 s here),
     * is cut at its end and the connection reset. Before, the channel's flush returned with the Close in it (the channel
     * held less than its capacity), the session counted it as written and ended at the engine's close with the server's
     * grace (1 s); the Close never left, and the connection's close, cut short by the engine's cleanup, ended the stream
     * inside a frame with a FIN (the server read `cut`). The connection is filled 64 KiB frame by frame until a frame
     * stays queued ([fillUntilAFrameStaysQueued]); the Close then fits behind it.
     */
    @Test fun negative_aCloseQueuedInFrontOfAFullKernelIsNotWritten() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val released = CompletableDeferred<Unit>()
            val handed = CompletableDeferred<io.kuicksilver.ktor.client.h1.H1Connection>()
            val closeWait = 3_000L
            try {
                coroutineScope {
                    val served =
                        async {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                val output = s.openWriteChannel(autoFlush = true)
                                output.writeStringUtf8(switchingProtocols(input.readWebSocketKey()))
                                released.await() // reads nothing before the engine's cleanup is over
                                probing(output) { readClientFrames(input, it) }
                            }
                        }
                    val c = testClient(block = { install(WebSockets) })
                    val e = c.engine as KuicksilverEngine
                    e.h1.webSocketCloseWaitMillis = closeWait
                    e.h1.webSocketConnectionForTest = { handed.complete(it) }
                    val port = (listener.localAddress as InetSocketAddress).port
                    val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                    val lifetime = session.call.attributes[WebSocketLifetimeKey]
                    val conn = withTimeout(10.seconds) { handed.await() }
                    val frame = ByteArray(64 * 1024)
                    val frames = fillUntilAFrameStaysQueued(session, conn, frame)
                    val started =
                        kotlin.time.TimeSource.Monotonic
                            .markNow()
                    launch { session.close(CloseReason(4002, "client bye")) }
                    session.call.coroutineContext[Job]!!.join()
                    c.close()
                    val endedEarly =
                        kotlinx.coroutines.withTimeoutOrNull((closeWait / 2).milliseconds) { e.cleanup.join() } != null
                    withTimeout((closeWait + 10_000).milliseconds) { e.cleanup.join() }
                    val took = started.elapsedNow()
                    released.complete(Unit)
                    val read = withTimeout(20.seconds) { served.await() }
                    assertTrue(read.none { it.startsWith("close") }, "a Close queued in front of a full kernel left: $read")
                    assertTrue(lifetime.cutByCloseWait, "a Close queued in front of the kernel counted as written ($took): $read")
                    assertEquals(false, endedEarly, "the engine's close cut short a writer that had not written its Close: $read")
                    assertTrue(read.dropLast(1).all { it == "binary ${frame.size}" }, "only whole frames before the end: $read")
                    assertTrue(read.size - 1 <= frames, "no more frames than were sent: $read")
                    assertEquals("reset", read.last(), "the connection was reset, not ended with a FIN: $read")
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * A server that reads slowly but steadily (256 KiB every 10 ms, then every 30 ms) as the client is closed: the writer
     * is not cut (the engine's close cuts no writer that has not written its Close; the close wait bounds it), so the
     * 16 MiB frame arrives whole and the Close after it, with no reset.
     */
    @Test fun clientCloseLetsAServerReading256KiBPer10msTakeTheFrameAndTheClose() =
        clientCloseWithAHeldWriter(throttle = 256 * 1024 to 10.milliseconds)

    @Test fun clientCloseLetsAServerReading256KiBPer30msTakeTheFrameAndTheClose() =
        clientCloseWithAHeldWriter(throttle = 256 * 1024 to 30.milliseconds)

    /**
     * One session that sends a frame of [BIG] and then its Close, and `client.close()` right after, to a server that starts
     * reading once the client was closed ([throttle]: that slowly); the server must read the frame and then the Close.
     */
    private fun clientCloseWithAHeldWriter(throttle: Pair<Int, kotlin.time.Duration>? = null) =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val reading = CompletableDeferred<Unit>()
            val engine = CompletableDeferred<KuicksilverEngine>()
            var cleanedBeforeTheClose: Boolean? = null
            try {
                coroutineScope {
                    val served =
                        async {
                            listener.accept().use { s ->
                                val input = s.openReadChannel()
                                val output = s.openWriteChannel(autoFlush = true)
                                output.writeStringUtf8(switchingProtocols(input.readWebSocketKey()))
                                reading.await()
                                val frames = readClientFrames(throttle?.let { (n, p) -> throttled(input, n, p) } ?: input)
                                cleanedBeforeTheClose = engine.await().cleanup.isCompleted
                                frames
                            }
                        }
                    val c = testClient(block = { install(WebSockets) })
                    val e = c.engine as KuicksilverEngine
                    engine.complete(e)
                    e.h1.webSocketCloseWaitMillis = 60_000
                    val port = (listener.localAddress as InetSocketAddress).port
                    val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                    session.outgoing.send(Frame.Binary(true, ByteArray(BIG)))
                    launch { session.close(CloseReason(4002, "client bye")) }
                    session.call.coroutineContext[Job]!!.join()
                    c.close()
                    reading.complete(Unit)
                    assertEquals(listOf("binary $BIG", "close 4002 client bye"), withTimeout(20.seconds) { served.await() })
                    // a throttled server reads the Close from its buffers after the client's socket took it: only an
                    // unthrottled one tells the cleanup's order
                    if (throttle == null) {
                        assertEquals(false, cleanedBeforeTheClose, "the cleanup ran before the session wrote its Close")
                    }
                    withTimeout(20.seconds) { e.cleanup.join() }
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * One attempt of the zero-reader tests for [unwrittenCloseAttempts]: a session sends [frames] frames of [data] and
     * then its Close to a server that reads nothing, its close wait [closeWait] ms; `client.close()` follows the end of the
     * call ([closeAt] later: a close late in T1). Returns what the server read once the engine's cleanup was over.
     *
     * Only an attempt whose Close never left is the case under test, and only there do its bounds hold: the session was
     * cut by its close wait, the engine's close did not cut it short (its cleanup still waits after half the close wait),
     * and a late close ended it at T1, counted from the session's own Close. When the buffers took the frames and the
     * Close within the close wait (the Android emulator's took a frame of 16 MiB and the Close: a sending buffer of up to
     * 8 MiB, a receiving one of up to 16 MiB), the session ended as one whose Close was written, not cut (a Close that
     * left from a cut writer fails), and [unwrittenCloseAttempts] checks the order of what arrived and repeats the
     * attempt with more frames.
     */
    private suspend fun zeroReaderAttempt(
        data: ByteArray,
        frames: Int,
        closeWait: Long,
        closeAt: kotlin.time.Duration? = null,
    ): List<String> {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        val reading = CompletableDeferred<Unit>()
        try {
            return coroutineScope {
                val served =
                    async {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            output.writeStringUtf8(switchingProtocols(input.readWebSocketKey()))
                            reading.await() // nothing is read before the engine's cleanup is over
                            readClientFrames(input)
                        }
                    }
                val c = testClient(block = { install(WebSockets) })
                val e = c.engine as KuicksilverEngine
                e.h1.webSocketCloseWaitMillis = closeWait
                val port = (listener.localAddress as InetSocketAddress).port
                val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                val lifetime = session.call.attributes[WebSocketLifetimeKey]
                repeat(frames) { session.outgoing.send(Frame.Binary(true, data)) }
                val started =
                    kotlin.time.TimeSource.Monotonic
                        .markNow()
                launch { session.close(CloseReason(4002, "client bye")) }
                session.call.coroutineContext[Job]!!.join()
                closeAt?.let { kotlinx.coroutines.delay(it) } // a close late in T1
                c.close()
                // not cut short by the engine's close: the session keeps its close wait
                val endedEarly =
                    closeAt == null &&
                        kotlinx.coroutines.withTimeoutOrNull((closeWait / 2).milliseconds) { e.cleanup.join() } != null
                withTimeout((closeWait + 10_000).milliseconds) { e.cleanup.join() }
                val took = started.elapsedNow()
                reading.complete(Unit)
                val read = withTimeout(20.seconds) { served.await() }
                if (read.any { it.startsWith("close") }) {
                    // the case not under test, but a Close that left must not be one of a writer the close wait cut
                    assertFalse(lifetime.cutByCloseWait, "the Close of a cut writer left after all: $read")
                } else {
                    assertTrue(lifetime.cutByCloseWait, "a writer whose Close never left was not cut at its T1: $read")
                    assertEquals(false, endedEarly, "the engine's close cut short a writer that had not written its Close: $read")
                    // a close late in T1 ends the session at its T1 all the same, not a close wait after the engine's close
                    if (closeAt != null) {
                        assertTrue(
                            took < (closeWait + 1_000).milliseconds,
                            "the cleanup ended $took after the own Close; T1 is $closeWait ms",
                        )
                    }
                }
                read
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /**
     * The invariant over many sessions of `webSocketSession()`: whatever data frames a session sends before `close(reason)`
     * (none to several, of random sizes), the server reads them all and then that Close, with its code and reason. The
     * server reads at once here, so the writer races the call's cancellation as it does in an application. Then the
     * closing order (RFC 6455 section 7.1.1): the server answers with its Close, the client waits for the server's TCP
     * close with its own side still open, and its FIN comes cleanly after the server's.
     *
     * A regression guard, not the test that shows the bug: over cleartext loopback the race is rare (the previous code
     * passed 200 sessions here; a TLS server under CPU load lost 73 of 4000 Closes), and the tests above force it.
     */
    @Test fun everyClosedSessionDeliversItsClose() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val sessions = 200
            val random = kotlin.random.Random(6455)
            try {
                coroutineScope {
                    val results = kotlinx.coroutines.channels.Channel<List<String>>(Channel.UNLIMITED)
                    val hooks = kotlinx.coroutines.channels.Channel<String>(Channel.UNLIMITED)
                    val served =
                        launch {
                            repeat(sessions) {
                                val s = listener.accept()
                                launch {
                                    s.use {
                                        val input = s.openReadChannel()
                                        val output = s.openWriteChannel(autoFlush = true)
                                        output.writeStringUtf8(switchingProtocols(input.readWebSocketKey()))
                                        val frames = readClientFrames(input)
                                        output.writeFully(byteArrayOf(0x88.toByte(), 2, 0x03, 0xE8.toByte()))
                                        output.flush()
                                        val order = ArrayList<String>()
                                        order += hooks.receive() // "waiting"
                                        if (input.isClosedForRead) order += "the client's FIN before the server's"
                                        output.flushAndClose()
                                        val clean = runCatching { input.discard() }.isSuccess && input.closedCause == null
                                        if (!clean) order += "the client's side ended without a clean FIN"
                                        order += hooks.receive() // "server closed"
                                        results.send(frames + order)
                                    }
                                }
                            }
                        }
                    // what each session's end did, for the message of one that did not end as it should
                    val seen = ArrayList<String>()
                    val ends = ArrayList<String>()
                    testClient(block = { install(WebSockets) }).use { c ->
                        (c.engine as KuicksilverEngine).h1.webSocketClosingForTest = {
                            seen += it
                            hooks.trySend(it)
                        }
                        (c.engine as KuicksilverEngine).h1.webSocketEndForTest = { end, why -> ends += "$end ($why)" }
                        var conn: io.kuicksilver.ktor.client.h1.H1Connection? = null
                        (c.engine as KuicksilverEngine).h1.webSocketConnectionForTest = { conn = it }
                        val port = (listener.localAddress as InetSocketAddress).port
                        repeat(sessions) { i ->
                            seen.clear()
                            ends.clear()
                            val sizes = List(random.nextInt(0, 4)) { random.nextInt(0, 200_000) }
                            val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                            val lifetime = session.call.attributes[WebSocketLifetimeKey]
                            for (size in sizes) session.outgoing.send(Frame.Binary(true, ByteArray(size)))
                            session.close(CloseReason((4000 + i).toShort(), "bye $i"))
                            val expected = sizes.map { "binary $it" } + "close ${4000 + i} bye $i" + "waiting" + "server closed"
                            val got =
                                kotlinx.coroutines.withTimeoutOrNull(20.seconds) { results.receive() }
                                    ?: kotlin.test.fail(
                                        "session $i ($sizes) did not end in order within 20 s: ${lifetime.stateForTest()}, " +
                                            "its end ${ends.toList()}, the hooks ${seen.toList()}, " +
                                            "not in the kernel yet ${conn?.let { k -> k.handedForTest?.let { k.pendingForTest(it()) } }}",
                                    )
                            assertEquals(expected, got, "session $i")
                        }
                    }
                    served.join()
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * The same against a server that never reads: the session gets the close wait (200 ms here) to write its Close, then
     * the connection is reset and given back, not held for good. The server, reading only once the connection was
     * released, finds the data cut off by the reset and no Close: what the session had not written by the end of the close
     * wait never leaves, not even what it had queued (a graceful close went on sending that, after the close wait, and
     * ended the cut frame with a FIN as if the stream were whole). [unwrittenCloseAttempts] repeats the attempt with more
     * data while the buffers take the Close.
     */
    @Test fun negative_anUnwrittenCloseIsBoundedByTheCloseWait() =
        clientTest(UNWRITTEN_CLOSE_TEST_TIMEOUT) {
            val read = unwrittenCloseAttempts { data, frames -> unwrittenCloseAttempt(data, frames) }
            assertEquals("reset", read.last(), "the connection was reset, not ended with a FIN: $read")
        }

    /**
     * One session that sends [frames] frames of [data] to a server that reads nothing, then its Close; the connection must
     * be released, not kept. Returns what the server read once it was.
     */
    private suspend fun unwrittenCloseAttempt(
        data: ByteArray,
        frames: Int,
    ): List<String> {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        val released = CompletableDeferred<Boolean>()
        val events =
            object : KuicksilverEventListener() {
                override fun connectionReleased(
                    request: io.ktor.client.request.HttpRequestData,
                    protocol: io.ktor.http.HttpProtocolVersion,
                    kept: Boolean,
                ) {
                    released.complete(kept)
                }
            }
        try {
            return coroutineScope {
                val served =
                    async {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            output.writeStringUtf8(switchingProtocols(input.readWebSocketKey()))
                            released.await() // reads nothing before the client gave the connection up
                            probing(output) { readClientFrames(input, it) }
                        }
                    }
                testClient(engine = { eventListener = events }, block = { install(WebSockets) }).use { c ->
                    (c.engine as KuicksilverEngine).h1.webSocketCloseWaitMillis = 200
                    val port = (listener.localAddress as InetSocketAddress).port
                    val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                    repeat(frames) { session.outgoing.send(Frame.Binary(true, data)) }
                    launch { session.close(CloseReason(4002, "client bye")) }
                    session.call.coroutineContext[Job]!!.join()
                    assertEquals(false, withTimeout(10.seconds) { released.await() }, "released, not kept")
                    withTimeout(20.seconds) { served.await() }
                }
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    private companion object {
        /**
         * More than the loopback socket and the channels in between take before the writer waits on most systems, not on
         * all (the Android emulator's buffers take it and a Close behind it): a test that needs the writer held there
         * sends more until it is ([unwrittenCloseAttempts]).
         */
        const val BIG = 16 shl 20
    }
}

/**
 * Attempts of a session that sends frames of 16 MiB to a server that reads nothing and then its Close, until one leaves
 * the Close unwritten; returns what the server read in that one (frames, then how the stream ended: `cut`, `end` or
 * `reset`, as [readClientFrames] says). [attempt] runs one session with that many frames and returns what the server read
 * once the connection was released, which it must check was released and not kept.
 *
 * That the Close cannot be written needs more data ahead of it than the way to a server that reads nothing takes: the
 * channels in between and both kernels' socket buffers, which the system sizes (Linux autotunes them up to `tcp_wmem` and
 * `tcp_rmem`: the Android emulator's 8 MiB and 16 MiB took a whole 16 MiB frame and the Close behind it within 200 ms, a
 * JVM on macOS or desktop Linux far less). So each attempt says which case it saw, from what the server read: a Close
 * that arrived was written within the close wait (all frames whole before it), and the attempt is repeated with twice the
 * frames, at most [MAX_UNWRITTEN_FRAMES].
 */
internal suspend fun unwrittenCloseAttempts(attempt: suspend (data: ByteArray, frames: Int) -> List<String>): List<String> {
    val size = 16 shl 20
    val data = ByteArray(size)
    var frames = 1
    while (true) {
        val read = attempt(data, frames)
        if (read.none { it.startsWith("close") }) {
            // the case under test: the data cut off (inside a frame or between two), and no Close after it
            assertTrue(read.dropLast(1).all { it == "binary $size" }, "only frames of the session before the end: $read")
            assertTrue(read.size - 1 <= frames, "no more frames than were sent: $read")
            return read
        }
        // everything, the Close included, fit into the buffers within the close wait: written in order
        assertEquals(
            List(frames) { "binary $size" } + "close 4002 client bye",
            read,
            "a Close that arrived was written within the close wait, after the data",
        )
        frames *= 2
        check(frames <= MAX_UNWRITTEN_FRAMES) { "$read: ${frames / 2} frames of $size bytes and the Close fit into the buffers" }
    }
}

/** The most frames [fillUntilAFrameStaysQueued] sends: 64 MiB of frames of 64 KiB. */
internal const val MAX_FILL_FRAMES: Int = 1024

/**
 * Sends [frame] on [session] (an HTTP/1.1 session on [conn]) one at a time until one stays queued in front of the kernel
 * of a peer that reads nothing: the kernels' socket buffers (and the peer's channel) are full. Returns the frames sent.
 * Stays queued means: bytes handed to the connection have not reached the kernel
 * ([io.kuicksilver.ktor.client.h1.H1Connection.pendingForTest], from the counts: the channels are not looked at from
 * outside their readers), and none of them did for 1 s (polled every 10 ms); a frame the kernel took all of is followed
 * by the next. After each frame a pause of 20 ms lets Ktor's writer hand it on. Fails after [MAX_FILL_FRAMES] frames: buffers
 * that take more than that are not what this models. Fails as well when more than 256 KiB wait at the end, so that a
 * Close still fits into the channel behind them: with a full channel the writer is held in its flush and has not written
 * its Close either way, which the other tests cover.
 */
internal suspend fun fillUntilAFrameStaysQueued(
    session: io.ktor.websocket.WebSocketSession,
    conn: io.kuicksilver.ktor.client.h1.H1Connection,
    frame: ByteArray,
): Int {
    var frames = 0
    while (true) {
        check(frames < MAX_FILL_FRAMES) {
            "$frames frames of ${frame.size} bytes went into the kernels' socket buffers and the server's channel"
        }
        session.outgoing.send(Frame.Binary(true, frame))
        frames++
        kotlinx.coroutines.delay(20) // Ktor's writer hands the frame on
        var seen = -1L
        var since =
            kotlin.time.TimeSource.Monotonic
                .markNow()
        while (true) {
            val now = conn.pendingForTest(conn.handedForTest!!.invoke())!!
            if (now <= 0L) break
            if (now != seen) {
                seen = now
                since =
                    kotlin.time.TimeSource.Monotonic
                        .markNow()
            } else if (since.elapsedNow() >= 1.seconds) {
                assertTrue(now in 1L..(256L * 1024), "$now bytes queued in front of the kernel after $frames frames")
                return frames
            }
            kotlinx.coroutines.delay(10)
        }
    }
}

/**
 * The bound of a test that runs [unwrittenCloseAttempts]: its worst case is four attempts (1, 2, 4 and 8 frames of
 * 16 MiB), each bounded by a close wait of up to 2 s, the cleanup's 10 s beyond it and the server's 20 s to read up to
 * 128 MiB, about 130 s in all where a normal run takes a few seconds; [clientTest]'s 60 s would cut such a worst case
 * short with a timeout that hides which attempt it was in. The attempts start at one frame: no probe tells the buffers'
 * size beforehand without the same cost as an attempt.
 */
internal val UNWRITTEN_CLOSE_TEST_TIMEOUT: kotlin.time.Duration = 150.seconds

/** The most frames of 16 MiB an attempt of [unwrittenCloseAttempts] sends. */
internal const val MAX_UNWRITTEN_FRAMES: Int = 8

/**
 * Runs [block] (reading what a client sent, counting it in the [ReadProgress] it is given) and, once the reading has
 * stalled, writes a byte to the client every 100 ms: a probe, so that a client whose connection is gone answers with a
 * reset. The abort's own reset always goes out, but macOS does not take one that reaches a socket whose receive window is
 * 0, as this server's is when the client aborts (it read nothing): on lo0 each abort's reset (flags R and ACK) is on the
 * wire, and in 8 of 22 runs without the probe the server stayed ESTABLISHED until its own close, which the client
 * answered with the same reset, taken then. A segment to a connection that is gone is always answered with one. Writes
 * that fail are ignored: they fail once the client reset the connection.
 *
 * The probe waits until nothing was read for [PROBE_STALL_TICKS] ticks of 100 ms, so that it cannot change the end it is
 * there to see. A byte that reaches a client which closed its socket makes the client's kernel answer with a reset, and a
 * reset drops what that kernel still had to send: a FIN turned into a reset. With the probe from the start, the FIN that
 * ended a cut frame (the bug `WebSocketTransportEndTest.negative_aWriterThatEndedInsideAFrameIsReset` guards) read as a
 * reset in all 5 such attempts of 40 in Docker (2026-11-18), and the test passed; it failed only when the FIN won the
 * race, in the local matrix. And on Linux a pending reset is reported once, to the first call that sees it: the reads
 * take the received data first, but a write in between takes the reset as its own error, and the reads then end as at
 * a FIN. While the reads progress, the client's data is still arriving; a stall is what the dropped reset of macOS
 * leaves.
 *
 * The probe also wakes the client's selector when the client's socket is still open (it had a read interest), which
 * releases a close the JDK deferred: these tests pass without `releaseClosedChannels`. The guard of that fix is
 * `IdleSelectorCloseTest` (ktor-network), whose idle sockets have no read interest.
 */
internal suspend fun <T> probing(
    output: io.ktor.utils.io.ByteWriteChannel,
    block: suspend (ReadProgress) -> T,
): T =
    coroutineScope {
        val progress = ReadProgress()
        val probe =
            launch {
                runCatching {
                    var seen = -1L
                    var still = 0
                    while (true) {
                        kotlinx.coroutines.delay(100)
                        val now = progress.bytes
                        if (now != seen) {
                            seen = now
                            still = 0
                        } else if (++still >= PROBE_STALL_TICKS) {
                            output.writeFully(byteArrayOf(0))
                            output.flush()
                        }
                    }
                }
            }
        try {
            block(progress)
        } finally {
            probe.cancel()
        }
    }

/** How long, in ticks of 100 ms without a byte read, [probing] waits before it probes. */
private const val PROBE_STALL_TICKS = 30

/** The bytes [readClientFrames] has read so far, for [probing]. */
internal class ReadProgress {
    @kotlin.concurrent.Volatile
    var bytes: Long = 0
}

/**
 * [input] as a server that reads slowly but steadily sees it: [chunk] bytes at a time (or to the end), a pause of
 * [pause] after each; the end or the failure of [input] ends the copy alike. The pause is the behaviour under test.
 */
internal fun CoroutineScope.throttled(
    input: ByteReadChannel,
    chunk: Int,
    pause: kotlin.time.Duration,
): ByteReadChannel {
    val out =
        io.ktor.utils.io
            .ByteChannel()
    launch {
        val buf = ByteArray(chunk)
        try {
            while (true) {
                var got = 0
                while (got < chunk) {
                    val n = input.readAvailable(buf, got, chunk - got)
                    if (n < 0) break
                    got += n
                }
                if (got > 0) {
                    out.writeFully(buf, 0, got)
                    out.flush()
                }
                if (got < chunk) break
                kotlinx.coroutines.delay(pause)
            }
            input.closedCause?.let { throw it }
            out.flushAndClose()
        } catch (e: Throwable) {
            out.cancel(e)
        }
    }
    return out
}

/**
 * The client's frames on [input] (masked, RFC 6455 section 5.3) up to its Close or the end of the stream: `binary <size>`,
 * `text <size>`, `close <code> <reason>`; when the stream ended without a Close, `end` between two frames, `cut` inside one
 * (the frame it cut keeps its line), `reset` when it failed (the client reset the connection) wherever it was.
 * [progress], when given, counts the bytes read as they come.
 */
internal suspend fun readClientFrames(
    input: ByteReadChannel,
    progress: ReadProgress? = null,
): List<String> {
    val frames = ArrayList<String>()
    try {
        readFramesInto(input, frames, progress)
    } catch (e: Exception) {
        frames +=
            when {
                input.closedCause != null -> "reset"

                // the stream failed: the client reset it
                e is FrameCut -> "cut"

                // it ended inside a frame
                else -> "end" // it ended between frames
            }
    }
    return frames
}

private suspend fun readFramesInto(
    input: ByteReadChannel,
    frames: MutableList<String>,
    progress: ReadProgress?,
) {
    while (true) {
        val b0 = input.readByte().toInt() and 0xff // the stream may end here, between frames
        progress?.let { it.bytes++ }
        try {
            readFrameAfter(b0, input, frames, progress)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: FrameCut) {
            throw e
        } catch (e: Exception) {
            throw FrameCut(e)
        }
        if (frames.last().startsWith("close")) return
    }
}

/** The stream ended inside a frame ([readClientFrames]). */
private class FrameCut(
    cause: Throwable? = null,
) : Exception(cause)

/** The rest of the frame whose first byte is [b0]. */
private suspend fun readFrameAfter(
    b0: Int,
    input: ByteReadChannel,
    frames: MutableList<String>,
    progress: ReadProgress?,
) {
    val b1 = input.readByte().toInt() and 0xff
    val length =
        when (val l = b1 and 0x7f) {
            126 -> input.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
            127 -> input.readByteArray(8).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
            else -> l.toLong()
        }
    val mask = input.readByteArray(4)
    when (b0 and 0x0f) {
        0x8 -> {
            val p = input.readByteArray(length.toInt())
            for (i in p.indices) p[i] = (p[i].toInt() xor mask[i % 4].toInt()).toByte()
            val code = if (p.size >= 2) ((p[0].toInt() and 0xff) shl 8) or (p[1].toInt() and 0xff) else -1
            frames += "close $code ${p.copyOfRange(minOf(2, p.size), p.size).decodeToString()}"
            return
        }

        0x2 -> {
            frames += "binary $length"
            discardCounted(input, length, progress)
        }

        0x1 -> {
            frames += "text $length"
            discardCounted(input, length, progress)
        }

        else -> {
            frames += "opcode ${b0 and 0x0f} $length"
            discardCounted(input, length, progress)
        }
    }
}

/** Discards [length] bytes of [input] in pieces, counted in [progress]; [EOFException] when the stream ends first. */
private suspend fun discardCounted(
    input: ByteReadChannel,
    length: Long,
    progress: ReadProgress?,
) {
    var left = length
    while (left > 0) {
        val n = input.discard(minOf(left, 64L * 1024))
        if (n == 0L) throw EOFException("frame cut")
        left -= n
        progress?.let { it.bytes += n }
    }
}
