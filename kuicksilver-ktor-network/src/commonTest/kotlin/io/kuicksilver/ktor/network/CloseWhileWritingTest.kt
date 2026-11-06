// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ClosedWriteChannelException
import io.ktor.utils.io.ConcurrentIOException
import io.ktor.utils.io.discard
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
import kotlin.time.Duration.Companion.seconds

/**
 * A socket's close() runs while the application may still write (TCP on the JVM and Native, TLS): it closes the
 * application's write channel with [closeFromSocketClose]. A write waiting for room (the peer reads slower than we write)
 * must end because the channel closed. ktor-io's suspending flushAndClose took the channel's single write slot instead,
 * and the waiting write was resumed with ConcurrentIOException, which escaped the application's coroutine (it also failed
 * the next runTest of the JVM as an uncaught exception from TcpWriterTest).
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
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
}
