// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/**
 * The end of an HTTP/2 request stream's handling ([releaseH2Stream]): a release that throws (an engine callback's
 * exception) gave the stream back all the same, so its failure is this stream's only: logged, never thrown into the
 * connection's scope, and suppressed under the handler's cancellation rather than in its place.
 */
class H2StreamReleaseTest {
    @Test fun negative_aReleaseThatThrowsIsLoggedNotThrown() {
        val log = CapturedLog()
        val failure = IllegalStateException("from the dispatch")
        releaseH2Stream(1, log, null) { throw failure }
        val line = log.lines.single()
        assertEquals("WARN", line.level)
        assertSame(failure, line.cause)
    }

    @Test fun negative_aReleaseThatThrowsUnderACancellationIsSuppressedUnderIt() {
        val log = CapturedLog()
        val cancelled = CancellationException("the handler was cancelled")
        val failure = IllegalStateException("from the dispatch")
        releaseH2Stream(3, log, cancelled) { throw failure }
        assertEquals(listOf<Throwable>(failure), cancelled.suppressedExceptions)
        assertSame(failure, log.lines.single().cause)
    }

    @Test fun aReleaseThatReturnsLogsNothing() {
        val log = CapturedLog()
        var released = false
        releaseH2Stream(5, log, null) { released = true }
        assertEquals(true, released)
        assertEquals(emptyList(), log.lines)
    }
}
