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
import kotlin.test.assertTrue
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
     * `close(reason)` and then `client.close()` at once, the writer still held behind a large frame: the engine's cleanup
     * (its pools, its selector) waits for the session to write its Close and end, instead of closing the connection under
     * it. Before, the cleanup ran as soon as the call ended and the handed-over socket stayed open past it, unaccounted.
     */
    @Test fun clientCloseWaitsForTheSessionsClose() =
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
                                reading.await()
                                readClientFrames(input)
                            }
                        }
                    val c = testClient(block = { install(WebSockets) })
                    val engine = c.engine as KuicksilverEngine
                    engine.h1.webSocketCloseWaitMillis = 60_000
                    val port = (listener.localAddress as InetSocketAddress).port
                    val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                    session.outgoing.send(Frame.Binary(true, ByteArray(BIG)))
                    launch { session.close(CloseReason(4002, "client bye")) }
                    session.call.coroutineContext[Job]!!.join()
                    c.close()
                    // a cleanup that does not wait for the session is over well within this
                    val cleanedFirst = kotlinx.coroutines.withTimeoutOrNull(1.seconds) { engine.cleanup.join() } != null
                    reading.complete(Unit)
                    assertEquals(listOf("binary $BIG", "close 4002 client bye"), withTimeout(20.seconds) { served.await() })
                    assertEquals(false, cleanedFirst, "the cleanup ran before the session wrote its Close")
                    withTimeout(20.seconds) { engine.cleanup.join() }
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
                    testClient(block = { install(WebSockets) }).use { c ->
                        (c.engine as KuicksilverEngine).h1.webSocketClosingForTest = { hooks.trySend(it) }
                        val port = (listener.localAddress as InetSocketAddress).port
                        repeat(sessions) { i ->
                            val sizes = List(random.nextInt(0, 4)) { random.nextInt(0, 200_000) }
                            val session = c.webSocketSession("ws://127.0.0.1:$port/ws")
                            for (size in sizes) session.outgoing.send(Frame.Binary(true, ByteArray(size)))
                            session.close(CloseReason((4000 + i).toShort(), "bye $i"))
                            val expected = sizes.map { "binary $it" } + "close ${4000 + i} bye $i" + "waiting" + "server closed"
                            assertEquals(expected, withTimeout(20.seconds) { results.receive() }, "session $i")
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
        clientTest {
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
        /** Far more than the loopback socket and the channels in between take before the writer waits. */
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
private const val PROBE_STALL_TICKS = 10

/** The bytes [readClientFrames] has read so far, for [probing]. */
internal class ReadProgress {
    @kotlin.concurrent.Volatile
    var bytes: Long = 0
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
