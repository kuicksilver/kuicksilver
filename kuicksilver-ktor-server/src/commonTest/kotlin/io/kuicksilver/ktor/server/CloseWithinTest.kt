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
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
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
            val closing = launch { closeWithin(sock, 45.seconds) }
            runCurrent()
            assertTrue(sock.closed, "no graceful close first")
            advanceTimeBy(45.seconds - 1.milliseconds)
            assertFalse(sock.socketContext.isCancelled, "aborted before the timeout")
            advanceTimeBy(2.milliseconds)
            assertTrue(sock.socketContext.isCancelled, "a close that does not finish leaves the socket open for ever")
            assertTrue(closing.isCompleted)
        }

    @Test fun gracefulCloseIsNotAborted() =
        runTest {
            val sock = FakeSocket(finishes = true)
            closeWithin(sock, 45.seconds)
            assertTrue(sock.socketContext.isCompleted)
            assertFalse(sock.socketContext.isCancelled)
        }
}
