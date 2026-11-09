// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.Source
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** [failureIsNoEnd] on its own. */
class FailedContentTest {
    /** A channel whose failure lands right after its cause was first read: the moment between the view's two reads. */
    @OptIn(InternalAPI::class)
    private class FailsAfterFirstCauseRead : ByteReadChannel {
        private var failed = false

        override val closedCause: Throwable?
            get() = (if (failed) IOException("cut") else null).also { failed = true }

        override val isClosedForRead: Boolean get() = failed // as ktor-io's ByteChannel: failed is "closed for read"
        override val readBuffer: Source = Buffer()

        override suspend fun awaitContent(min: Int): Boolean = false

        override fun cancel(cause: Throwable?) {}
    }

    /** A failure between the view's reads of the cause and of the state was taken for a clean end. */
    @Test fun negative_aFailureBetweenTheReadsIsNoEnd() {
        assertFalse(FailsAfterFirstCauseRead().failureIsNoEnd().isClosedForRead)
    }

    /**
     * A channel cancelled together with its reader's call, as a `writer {}` of the call's scope is: the first look at its
     * state finds both cancelled.
     */
    @OptIn(InternalAPI::class)
    private class CancelledWithTheReader : ByteReadChannel {
        var reader: Job? = null
        private var cause: Throwable? = null

        private fun land() {
            if (cause == null) {
                reader?.cancel()
                cause = CancellationException("the writer was cancelled with the call")
            }
        }

        override val closedCause: Throwable? get() {
            land()
            return cause
        }
        override val isClosedForRead: Boolean get() {
            land()
            return true
        }
        override val readBuffer: Source get() = throw cause!!

        override suspend fun awaitContent(min: Int): Boolean = throw cause!!

        override fun cancel(cause: Throwable?) {}
    }

    /** The call's own cancellation ends the copy as a cancellation, not as the IOException of a failed channel (an error). */
    @Test fun negative_aCancelledCallEndsTheCopyWithItsCancellation() =
        runTest {
            val content = CancelledWithTheReader()
            val ended = CompletableDeferred<Throwable>()
            launch {
                content.reader = coroutineContext.job
                try {
                    ByteChannel().copyContentFrom(content, null)
                } catch (e: Throwable) {
                    ended.complete(e)
                    throw e
                }
            }.join()
            val e = ended.await()
            assertTrue(e is CancellationException, "the copy ended with ${e.stackTraceToString()}")
        }
}
