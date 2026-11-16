// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.websocket.Frame
import io.ktor.websocket.WebSocketSession
import io.ktor.websocket.readReason
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

    /** Records [KuicksilverEventListener.webSocketFailed]. */
    private class Failures : KuicksilverEventListener() {
        val failed = CompletableDeferred<Throwable>()

        override fun webSocketFailed(
            request: io.ktor.client.request.HttpRequestData,
            cause: Throwable,
        ) {
            failed.complete(cause)
        }
    }

    private class Setup(
        closeWait: Long = 60_000,
        val listener: Failures = Failures(),
        /** Whether the session was made ([WebSocketLifetime.watch]): false for a handshake still under way. */
        watched: Boolean = true,
    ) {
        val call = Job()

        /** The engine's in-flight job of the call: it waits for the session's end. */
        val inFlight = Job()
        val data =
            io.ktor.client.request.HttpRequestBuilder().build().also {
                it.attributes.put(
                    WebSocketCallTrackKey,
                    WebSocketCallTrack(inFlight, EngineEvents(listener, io.kuicksilver.quic.KuicksilverLogger.None)),
                )
            }
        val lifetime = WebSocketLifetime(data, call, closeWait)
        val ended = CompletableDeferred<Throwable?>()

        // the session's writer: runs until released (or cancelled)
        val release = CompletableDeferred<Unit>()
        val writer = kotlinx.coroutines.CoroutineScope(lifetime.context).launch { release.await() }
        val raw = NullSession(lifetime.context)
        val session = if (watched) lifetime.watch(raw) else raw

        /** The Close frames that reached the session's own outgoing channel, as codes. */
        fun closesSent(): List<Short?> =
            generateSequence { raw.outgoing.tryReceive().getOrNull() }
                .filterIsInstance<Frame.Close>()
                .map { it.readReason()?.code }
                .toList()

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

    /**
     * A call cancelled before the session queued its own Close: the established session still closes with one Close
     * frame, 1001 Going Away (RFC 6455 sections 7.1.7 and 7.3), and its coroutines go on within the close wait to write it
     * and read the server's; the session ends in order. Before, it was cancelled at once, without a Close.
     */
    @Test fun negative_aCallCancelledBeforeTheOwnCloseClosesTheSessionWith1001(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                s.call.cancel(CancellationException("the application gave up"))
                s.call.join()
                assertTrue(s.lifetime.ownCloseQueued, "the session's Close")
                assertEquals(listOf<Short?>(1001), s.closesSent(), "one Close, Going Away")
                assertTrue(s.writer.isActive, "the writer goes on to write it")
                s.release.complete(Unit)
                s.writer.join()
                assertNull(s.ended.await(), "the session ended in order")
            }
        }

    /** A handshake still under way ([WebSocketLifetime.watch] not called): there is no session to close, it is cancelled. */
    @Test fun aCallCancelledBeforeTheSessionWasMadeCancelsItAtOnce(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup(watched = false)
                s.call.cancel(CancellationException("the application gave up"))
                s.writer.join()
                assertTrue(s.writer.isCancelled, "the session's coroutines are cancelled with the call")
                assertIs<CancellationException>(s.ended.await())
                assertEquals(emptyList(), s.closesSent())
            }
        }

    /**
     * Ktor's session answers its call's cancellation by closing its outgoing channel, and its processor then sends a Close
     * 1000 without a reason: whichever comes first, it or the lifetime's own, exactly one Close goes out, and it is 1001
     * Going Away. Before, that Close went out as 1000 when it came first (about once in 400 runs on a loaded host).
     */
    @Test fun negative_aCloseKtorSendsBecauseTheCallIsCancelledGoesOutOnceAs1001(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                // as Ktor's outgoing processor does: a coroutine of the call that sends a Close once the call is cancelled
                val processor =
                    kotlinx.coroutines.CoroutineScope(s.call).launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                        try {
                            kotlinx.coroutines.awaitCancellation()
                        } finally {
                            kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
                                s.session.outgoing.send(Frame.Close(io.ktor.websocket.CloseReason(1000, "")))
                            }
                        }
                    }
                s.call.cancel(CancellationException("the application gave up"))
                processor.join()
                s.call.join()
                assertEquals(listOf<Short?>(1001), s.closesSent(), "one Close, Going Away")
                assertFalse(s.lifetime.cutByCloseWait)
            }
        }

    /** The application's own Close from a `finally` of a cancelled call keeps its code; nothing is sent after it. */
    @Test fun negative_anApplicationsCloseFromAFinallyKeepsItsCode(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                val app =
                    kotlinx.coroutines.CoroutineScope(s.call).launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                        try {
                            kotlinx.coroutines.awaitCancellation()
                        } finally {
                            kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
                                s.session.outgoing.send(Frame.Close(io.ktor.websocket.CloseReason(4000, "bye")))
                                s.session.outgoing.send(Frame.Close(io.ktor.websocket.CloseReason(1000, ""))) // a second
                            }
                        }
                    }
                s.call.cancel(CancellationException("the application gave up"))
                app.join()
                s.call.join()
                assertEquals(listOf<Short?>(4000), s.closesSent(), "the application's Close, once")
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
                assertTrue(s.lifetime.cutByCloseWait, "cut by the close wait: what it queued must not leave")
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
                assertEquals(failure, withTimeout(10.seconds) { s.listener.failed.await() }, "reported to the listener")
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

    /**
     * The engine's in-flight job of the call (its cleanup after `client.close()` waits for it) completes only after the
     * session's end handlers ran, also when the call ended long before: the pools are not closed under a session that is
     * still writing its Close.
     */
    @Test fun theEngineWaitsForTheSessionsEndNotTheCalls(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                val handlerRan = CompletableDeferred<Unit>()
                val releaseHandler = CompletableDeferred<Unit>()
                s.lifetime.invokeOnEnd {
                    handlerRan.complete(Unit)
                    releaseHandler.await() // a transport's bounded wait (HTTP/2: the server's END_STREAM)
                }
                s.session.outgoing.send(Frame.Close())
                s.call.cancel(CancellationException("Ktor's webSocketSession() after the Close"))
                s.inFlight.complete()
                s.call.join()
                assertFalse(s.inFlight.isCompleted, "in flight while the session writes its Close")
                s.release.complete(Unit)
                handlerRan.await()
                assertFalse(s.inFlight.isCompleted, "in flight while an end handler runs")
                releaseHandler.complete(Unit)
                s.inFlight.join()
            }
        }

    /**
     * A lifetime given up before its session was made (a refused answer, a request that goes again): a call that then ends
     * in order is not held by it, its handlers run with the cause, and the request no longer names it.
     */
    @Test fun negative_anAbandonedLifetimeHoldsNothing(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val call = Job()
                val inFlight = Job()
                val data =
                    io.ktor.client.request
                        .HttpRequestBuilder()
                        .build()
                data.attributes.put(
                    WebSocketCallTrackKey,
                    WebSocketCallTrack(inFlight, EngineEvents(null, io.kuicksilver.quic.KuicksilverLogger.None)),
                )
                val lifetime = WebSocketLifetime(data, call, 60_000)
                val ended = CompletableDeferred<Throwable?>()
                lifetime.invokeOnEnd { ended.complete(it) }
                assertTrue(data.attributes.getOrNull(WebSocketLifetimeKey) === lifetime)
                val refused = IllegalStateException("handshake refused")
                lifetime.abandon(refused)
                assertNull(data.attributes.getOrNull(WebSocketLifetimeKey))
                call.complete() // the retry's call ends in order
                call.join()
                assertFalse(call.isCancelled)
                assertTrue(ended.await() != null, "the end handlers see the abandon")
                inFlight.complete()
                inFlight.join()
            }
        }

    /** One deadline, counted from the session's own Close: what is left of it shrinks, never restarts. */
    @Test fun theCloseWaitCountsFromTheOwnClose(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup(closeWait = 60_000)
                assertEquals(60_000, s.lifetime.remainingCloseWaitMillis(), "the whole wait before the own Close")
                s.session.outgoing.send(Frame.Close())
                val first = s.lifetime.remainingCloseWaitMillis()
                assertTrue(first in 1..60_000, "$first")
                s.session.outgoing.send(Frame.Close()) // a second Close does not restart it
                assertTrue(s.lifetime.remainingCloseWaitMillis() <= first)
                s.release.complete(Unit)
                s.call.complete()
                s.call.join()
            }
        }

    /** A handler that fails, a cancellation included, does not keep the later ones (the HTTP/3 pool's release) from running. */
    @Test fun negative_aFailingEndHandlerDoesNotStopTheNextOnes(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup()
                val last = CompletableDeferred<Unit>()
                s.lifetime.invokeOnEnd { throw CancellationException("a handler's own cancellation") }
                s.lifetime.invokeOnEnd { throw IllegalStateException("a handler's failure") }
                s.lifetime.invokeOnEnd { last.complete(Unit) }
                s.release.complete(Unit)
                s.call.complete()
                s.inFlight.complete()
                last.await()
                s.inFlight.join()
            }
        }

    /**
     * The end handlers run within one close wait (200 ms here): one that never returns is cancelled there, the ones after
     * it still run, and the engine's in-flight job completes, so `client.close()` is not held for good.
     */
    @Test fun negative_anEndHandlerThatNeverReturnsIsBounded(): Unit =
        runBlocking {
            withTimeout(10.seconds) {
                val s = Setup(closeWait = 200)
                val cancelled = CompletableDeferred<Unit>()
                val after = CompletableDeferred<Unit>()
                s.lifetime.invokeOnEnd {
                    try {
                        kotlinx.coroutines.awaitCancellation()
                    } finally {
                        cancelled.complete(Unit)
                    }
                }
                s.lifetime.invokeOnEnd { after.complete(Unit) }
                s.release.complete(Unit)
                s.call.complete()
                s.inFlight.complete()
                s.inFlight.join()
                cancelled.await()
                after.await()
            }
        }
}
