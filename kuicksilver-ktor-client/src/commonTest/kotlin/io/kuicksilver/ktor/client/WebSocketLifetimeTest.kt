// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * [WebSocketLifetime]: the session's coroutines outlive a call cancelled after the session's own Close was queued (within
 * the close wait), and only then; a call that ends in order waits for them as before.
 */
class WebSocketLifetimeTest {
    /** A session whose outgoing frames go nowhere: only what passes through [WebSocketLifetime.watch] matters here. */
    private class NullSession(
        override val coroutineContext: CoroutineContext,
    ) : WebSocketSession {
        override var masking = false
        override var maxFrameSize = Long.MAX_VALUE
        override val incoming = Channel<Frame>()
        override val outgoing = Channel<Frame>(Channel.UNLIMITED)
        override val extensions = emptyList<io.ktor.websocket.WebSocketExtension<*>>()

        override suspend fun flush() {}

        @Deprecated("Use cancel() instead.", level = DeprecationLevel.ERROR)
        override fun terminate() {}
    }

    private class Setup(
        closeWait: Long = 60_000,
    ) {
        val call = Job()
        val lifetime = WebSocketLifetime(call, closeWait)
        val ended = CompletableDeferred<Throwable?>()

        // the session's writer: runs until released (or cancelled)
        val release = CompletableDeferred<Unit>()
        val writer = kotlinx.coroutines.CoroutineScope(lifetime.context).launch { release.await() }
        val session = lifetime.watch(NullSession(lifetime.context))

        init {
            lifetime.invokeOnEnd { ended.complete(it) }
        }
    }

    @Test fun aCallEndingInOrderWaitsForTheSession(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                s.call.complete()
                assertFalse(s.call.isCompleted, "the call waits for the session's coroutines")
                s.release.complete(Unit)
                s.call.join()
                assertFalse(s.call.isCancelled)
                assertNull(s.ended.await())
            }
        }

    @Test fun negative_aCallCancelledBeforeTheOwnCloseCancelsTheSessionAtOnce(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                s.call.cancel(CancellationException("the application gave up"))
                s.writer.join()
                assertTrue(s.writer.isCancelled, "the session's writer is cancelled with the call")
                assertIs<CancellationException>(s.ended.await())
            }
        }

    @Test fun aCallCancelledAfterTheOwnCloseLetsTheSessionFinish(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                s.session.outgoing.send(Frame.Close())
                assertTrue(s.lifetime.ownCloseQueued)
                s.call.cancel(CancellationException("Ktor's webSocketSession() after the Close"))
                s.call.join()
                assertTrue(s.writer.isActive, "the writer outlives the call")
                s.release.complete(Unit)
                s.writer.join()
                assertFalse(s.writer.isCancelled)
                assertNull(s.ended.await(), "the session ended in order")
            }
        }

    /** The Close sent through the session's `send` (Ktor's `close()`) and `trySend` count too. */
    @Test fun everySendPathOfTheOwnCloseCounts(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val viaSend = Setup()
                viaSend.session.send(Frame.Close())
                assertTrue(viaSend.lifetime.ownCloseQueued)
                val viaTrySend = Setup()
                assertTrue(
                    viaTrySend.session.outgoing
                        .trySend(Frame.Close())
                        .isSuccess,
                )
                assertTrue(viaTrySend.lifetime.ownCloseQueued)
                val notAClose = Setup()
                notAClose.session.outgoing.send(Frame.Text("x"))
                assertFalse(notAClose.lifetime.ownCloseQueued, "a data frame is no Close")
                for (s in listOf(viaSend, viaTrySend, notAClose)) {
                    s.release.complete(Unit)
                    s.call.complete()
                    s.call.join()
                }
            }
        }

    @Test fun negative_aSessionThatDoesNotFinishWithinTheCloseWaitIsCancelled(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup(closeWait = 100)
                s.session.outgoing.send(Frame.Close())
                s.call.cancel(CancellationException("after the Close"))
                // the writer never finishes on its own
                s.writer.join()
                assertTrue(s.writer.isCancelled, "cancelled once the close wait is over")
                assertIs<CancellationException>(s.ended.await())
            }
        }

    @Test fun negative_aSessionCancelledOnItsOwnEndsWithItsCause(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                val failure = IllegalStateException("the writer failed")
                kotlinx.coroutines
                    .CoroutineScope(s.lifetime.context)
                    .launch { throw failure }
                    .join()
                s.call.complete()
                s.call.join()
                assertTrue(s.writer.isCancelled, "a failing child cancels the session")
                val cause = s.ended.await()
                assertEquals(failure, cause?.let { generateSequence(it) { c -> c.cause }.firstOrNull { c -> c is IllegalStateException } })
            }
        }

    @Test fun anEndHandlerAddedAfterTheEndRunsAtOnce(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                s.release.complete(Unit)
                s.call.complete()
                s.call.join()
                val late = CompletableDeferred<Throwable?>()
                s.lifetime.invokeOnEnd { late.complete(it) }
                assertNull(late.await())
            }
        }
}
