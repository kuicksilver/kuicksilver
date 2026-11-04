// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ClosedWriteChannelException
import io.ktor.utils.io.ConcurrentIOException
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * A socket's close() runs while the application may still write (TCP on the JVM and Native, TLS): it closes the
 * application's write channel with [closeFromSocketClose]. A write waiting for room (the peer reads slower than we write)
 * must end because the channel closed. ktor-io's suspending flushAndClose took the channel's single write slot instead,
 * and the waiting write was resumed with ConcurrentIOException, which escaped the application's coroutine (it also failed
 * the next runTest of the JVM as an uncaught exception from TcpWriterTest).
 */
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
            val queued = channel.readRemaining().readByteArray().size
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
}
