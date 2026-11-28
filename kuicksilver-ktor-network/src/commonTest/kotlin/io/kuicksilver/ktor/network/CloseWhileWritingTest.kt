// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ClosedWriteChannelException
import io.ktor.utils.io.ConcurrentIOException
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A socket's close() runs while the application may still write (TCP on the JVM and Native, TLS): it closes the
 * application's write channel with [closeFromSocketClose]. A write waiting for room (the peer reads slower than we write)
 * must end because the channel closed. ktor-io's suspending flushAndClose took the channel's single write slot instead,
 * and the waiting write was resumed with ConcurrentIOException, which escaped the application's coroutine (it also failed
 * the next runTest of the JVM as an uncaught exception from TcpWriterTest).
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
class CloseWhileWritingTest {
    /**
     * An application writing 512 KiB at a time into a channel nobody reads: ktor-io holds 1 MiB, so a write waits
     * for room. [ended] is how its writes ended.
     */
    private fun kotlinx.coroutines.test.TestScope.waitingWrite(
        channel: ByteChannel,
        ended: CompletableDeferred<Throwable?>,
    ) = launch {
        try {
            repeat(64) { channel.writeFully(ByteArray(512 shl 10)) }
            ended.complete(null)
        } catch (e: Throwable) {
            ended.complete(e)
        }
    }

    @Test fun negative_closeWhileAWriteWaitsForRoomEndsItAsClosed() =
        runTest {
            val channel = ByteChannel()
            val ended = CompletableDeferred<Throwable?>()
            waitingWrite(channel, ended)
            runCurrent()
            assertTrue(!ended.isCompleted, "the write waits for room")
            launch { channel.closeFromSocketClose() }
            runCurrent()
            val failure = ended.await()
            assertTrue(failure is ClosedWriteChannelException, "the waiting write ends as closed, got $failure")
            // what was handed over before the close is still there for the socket's writer
            val queued = channel.readBuffer().readByteArray().size
            assertTrue(queued >= 1 shl 20 && queued % (512 shl 10) == 0, "queued $queued")
        }

    /** The cause: ktor-io's flushAndClose next to a waiting write hands that write ConcurrentIOException. */
    @Test fun flushAndCloseNextToAWaitingWriteFailsIt() =
        runTest {
            val channel = ByteChannel()
            val ended = CompletableDeferred<Throwable?>()
            waitingWrite(channel, ended)
            runCurrent()
            launch { runCatching { channel.flushAndClose() } }
            runCurrent()
            assertTrue(ended.await() is ConcurrentIOException, "ktor-io ${ended.getCompleted()}")
            channel.cancel(null)
        }

    /**
     * The TLS socket's close keeps its order with a write still queued: the application's channel is drained through the
     * session before close_notify and the raw socket's close, so the peer reads every byte, then a clean end. A close that
     * did not wait for that drain would end the stream early with close_notify, a cut stream that reads as complete.
     */
    @Test fun tlsCloseSendsEverythingQueuedBeforeCloseNotify() =
        kotlinx.coroutines.runBlocking {
            val size = 4 shl 20
            val gate = CompletableDeferred<Unit>()
            val received = CompletableDeferred<Long>()
            val srv =
                LoopbackServer.start { s ->
                    gate.await() // the client has closed with its write still queued
                    received.complete(s.openReadChannel().discard())
                }
            try {
                val c = kotlinx.coroutines.withTimeout(20.seconds) { srv.client() }
                val out = c.openWriteChannel(autoFlush = true)
                // UNDISPATCHED: the write hands over all its bytes before it waits for room
                launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { runCatching { out.writeFully(ByteArray(size)) } }
                c.close()
                gate.complete(Unit)
                val read = kotlinx.coroutines.withTimeout(60.seconds) { received.await() }
                assertEquals(size.toLong(), read, "every byte queued before close(), then close_notify")
            } finally {
                srv.close()
            }
        }

    /**
     * The close of an [autoFlush][ByteChannel.autoFlush] channel (the client engine's) under a write running on another
     * thread: the reader gets a prefix of what was written, in order, then the end; the write ends as closed. Before,
     * close() moved the channel's write buffer to the reader while the write filled it: on the JVM 3 to 8 of 20000 closes
     * failed with a NullPointerException in kotlinx-io's Buffer.write, the write and the reader then waiting for good
     * (closeFromSocketClose). A race, so many rounds; each round's close comes a little later.
     */
    @Test fun negative_aCloseUnderARunningWriteLeavesTheStreamWhole() =
        kotlinx.coroutines.runBlocking {
            val odd = ArrayList<String>()
            repeat(CLOSE_RACE_ROUNDS) { round ->
                val channel = ByteChannel(autoFlush = true)
                val wrote = CompletableDeferred<Throwable?>()
                val read = CompletableDeferred<String?>()
                val writing = kotlin.concurrent.atomics.AtomicInt(0)
                launch(kotlinx.coroutines.Dispatchers.Default) {
                    val chunk = ByteArray(1 + round % 3000)
                    var next = 0
                    try {
                        while (true) {
                            for (j in chunk.indices) chunk[j] = (next++).toByte()
                            channel.writeFully(chunk)
                            writing.store(1)
                        }
                    } catch (e: Throwable) {
                        wrote.complete(e)
                    }
                }
                launch(kotlinx.coroutines.Dispatchers.Default) {
                    val buf = ByteArray(8192)
                    var next = 0
                    try {
                        while (true) {
                            val n = channel.readAvailable(buf)
                            if (n < 0) break
                            for (j in 0 until n) {
                                if (buf[j] != (next++).toByte()) {
                                    read.complete("byte ${next - 1} out of order")
                                    return@launch
                                }
                            }
                        }
                        read.complete(null)
                    } catch (e: Throwable) {
                        read.complete("the read failed: $e")
                    }
                }
                // once the write runs, and a little later each round (0 to 49 µs)
                while (writing.load() == 0) kotlinx.coroutines.yield()
                val until =
                    kotlin.time.TimeSource.Monotonic
                        .markNow() + (round % 50).microseconds
                while (until.hasNotPassedNow()) {
                    // spins: a suspension would hand the thread over and lose the moment
                }
                val closed = runCatching { channel.closeFromSocketClose() }.exceptionOrNull()
                if (closed != null) odd += "round $round: the close failed: $closed"
                val writeEnd = kotlinx.coroutines.withTimeoutOrNull(5.seconds) { wrote.await() }
                val readEnd = kotlinx.coroutines.withTimeoutOrNull(5.seconds) { read.await() }
                if (writeEnd !is ClosedWriteChannelException) odd += "round $round: the write ended with $writeEnd"
                if (!read.isCompleted) odd += "round $round: the reader never saw the end"
                readEnd?.let { odd += "round $round: $it" }
                channel.cancel(null)
            }
            assertEquals(emptyList<String>(), odd.take(10), "${odd.size} of $CLOSE_RACE_ROUNDS rounds")
        }

    /**
     * What [closeFromSocketClose] relies on: ktor-io's `cancel(null)` is a clean end, as close() without its move. The
     * bytes flushed before it stay readable, then the end comes without a cause; a later write fails as closed.
     */
    @Test fun cancelWithoutACauseEndsAChannelCleanly() =
        runTest {
            val channel = ByteChannel(autoFlush = true)
            channel.writeFully(ByteArray(1000) { it.toByte() })
            channel.closeFromSocketClose()
            assertTrue(channel.isClosedForWrite, "closed for write")
            assertEquals(null, channel.closedCause, "no cause")
            assertEquals(1000, channel.readBuffer().readByteArray().size, "the flushed bytes")
            assertTrue(channel.isClosedForRead && channel.closedCause == null, "a clean end")
            val late = runCatching { channel.writeFully(ByteArray(1)) }.exceptionOrNull()
            assertTrue(late is ClosedWriteChannelException, "a later write fails as closed, got $late")
        }

    private companion object {
        /** Rounds of the close race: a few seconds on the JVM, where 3 to 8 of 20000 failed before. */
        const val CLOSE_RACE_ROUNDS = 20_000
    }
}
