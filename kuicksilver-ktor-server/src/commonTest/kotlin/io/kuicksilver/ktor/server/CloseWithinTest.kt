// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Closing a connection's socket: a graceful close first (what was written is still sent), aborted after the timeout. A
 * client that never reads keeps a graceful close (the socket's write loop, and with it the descriptor) waiting for ever.
 */
class CloseWithinTest {
    /** A socket whose graceful close finishes only when [finishes]. */
    private class FakeSocket(
        val finishes: Boolean,
    ) : Socket {
        override val socketContext: CompletableJob = Job()
        override val coroutineContext: CoroutineContext get() = socketContext
        override val localAddress: SocketAddress = InetSocketAddress("127.0.0.1", 1)
        override val remoteAddress: SocketAddress = InetSocketAddress("127.0.0.1", 2)
        var closed = false

        override fun close() {
            closed = true
            if (finishes) socketContext.complete()
        }

        override fun dispose() = close()

        override fun attachForReading(channel: ByteChannel): WriterJob = error("not used")

        override fun attachForWriting(channel: ByteChannel): ReaderJob = error("not used")
    }

    @Test fun negative_closeThatDoesNotFinishIsAbortedAfterTheTimeout() =
        runTest {
            val sock = FakeSocket(finishes = false)
            var abortedAt = -1L
            val closing =
                launch {
                    closeWithin(sock, {
                        abortedAt = currentTime
                        sock.socketContext.complete() // an abort that releases the socket
                    }, 45.seconds)
                }
            runCurrent()
            assertTrue(sock.closed, "no graceful close first")
            advanceTimeBy(45.seconds - 1.milliseconds)
            assertEquals(-1L, abortedAt, "aborted before the timeout")
            advanceTimeBy(2.milliseconds)
            assertEquals(45_000L, abortedAt, "a close that does not finish leaves the socket open for ever")
            runCurrent()
            assertTrue(closing.isCompleted)
            assertFalse(sock.socketContext.isCancelled, "released by the abort, no last-resort cancel")
        }

    /** The engine reports a connection closed when [closeWithin] returns: only once the aborted socket is released. */
    @Test fun returnsOnceTheAbortedSocketIsReleased() =
        runTest {
            val sock = FakeSocket(finishes = false)
            val closing =
                launch {
                    closeWithin(sock, {
                        launch {
                            delay(500.milliseconds)
                            sock.socketContext.complete()
                        }
                    }, 45.seconds)
                }
            advanceTimeBy(45.seconds + 499.milliseconds)
            assertTrue(closing.isActive, "returned before the socket was released")
            advanceTimeBy(2.milliseconds)
            assertTrue(closing.isCompleted)
        }

    /** An abort that does not release the socket is followed by a cancel of its job, after a bounded wait. */
    @Test fun abortThatDoesNotReleaseEndsInACancel() =
        runTest {
            val sock = FakeSocket(finishes = false)
            val closing = launch { closeWithin(sock, {}, 45.seconds) }
            advanceTimeBy(48.seconds + 1.milliseconds) // the stall, then 3 s for the aborted socket to go
            assertTrue(closing.isCompleted)
            assertTrue(sock.socketContext.isCancelled)
        }

    /**
     * The bound is on progress, not on the close: a drain that keeps moving (a slow reader taking its last response) is
     * never aborted, however long it takes; once it stops moving, the abort comes [stall] later.
     */
    @Test fun negative_aDrainThatMovesIsNotCutOnlyOneThatStops() =
        runTest {
            val sock = FakeSocket(finishes = false)
            var sent = 0L
            var abortedAt = -1L
            val mover =
                launch {
                    repeat(10) {
                        delay(10.seconds)
                        sent += 4096 // the client took some more
                    }
                }
            val closing =
                launch {
                    closeWithin(sock, {
                        abortedAt = currentTime
                        sock.socketContext.complete()
                    }, 45.seconds, progress = { sent })
                }
            advanceTimeBy(100.seconds)
            assertEquals(-1L, abortedAt, "a drain that moves was aborted")
            mover.join()
            advanceTimeBy(46.seconds)
            assertEquals(145_000L, abortedAt, "a drain that stopped at 100 s is aborted 45 s later")
            assertTrue(closing.isCompleted)
        }

    /** With no stall deadline left (the client was cut for not reading), the close aborts at once. */
    @Test fun aZeroDeadlineAbortsAtOnce() =
        runTest {
            val sock = FakeSocket(finishes = false)
            var abortedAt = -1L
            closeWithin(sock, {
                abortedAt = currentTime
                sock.socketContext.complete()
            }, kotlin.time.Duration.ZERO)
            assertEquals(0L, abortedAt)
        }

    @Test fun gracefulCloseIsNotAborted() =
        runTest {
            val sock = FakeSocket(finishes = true)
            var aborted = false
            closeWithin(sock, { aborted = true }, 45.seconds)
            assertTrue(sock.socketContext.isCompleted)
            assertFalse(sock.socketContext.isCancelled)
            assertFalse(aborted)
        }
}
