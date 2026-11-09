// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.Source
import kotlin.test.Test
import kotlin.test.assertFalse

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
}
