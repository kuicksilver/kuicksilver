// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

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

    /**
     * The handler's own end: a client's RST_STREAM cancels it, and that cancellation, in flight, carries the release's
     * failure (stack-trace recovery copies a cancellation per suspension in tests, so the test takes the one the handler
     * passes on, not the route's).
     */
    @Test fun negative_aHandlerCancelledByAResetCarriesTheReleaseFailure() =
        serverTest {
            val log = CapturedLog()
            val started = CompletableDeferred<Unit>()
            val inFlight = CompletableDeferred<CancellationException?>()
            val failure = IllegalStateException("from the dispatch")
            val (server, port) =
                h2TlsServer(
                    configure = {
                        h2ReleaseForTest = { r, cancelled ->
                            r.release()
                            inFlight.complete(cancelled)
                            throw failure
                        }
                    },
                    log = log,
                ) {
                    routing {
                        get("/hold") {
                            started.complete(Unit)
                            awaitCancellation()
                        }
                    }
                }
            try {
                RawH2Client.connect(port).use { raw ->
                    raw.preface()
                    assertNotNull(raw.await { it.type == RawFrame.SETTINGS && it.flags and 1 == 0 })
                    raw.headers(1, RawH2Client.get("/hold"))
                    withTimeout(10.seconds) { started.await() }
                    raw.rstStream(1, 8) // CANCEL
                    val e = assertNotNull(withTimeout(10.seconds) { inFlight.await() }, "the handler's cancellation")
                    // logged, then suppressed under the cancellation, once the release returned
                    withTimeout(10.seconds) { while (e.suppressedExceptions.isEmpty()) delay(10) }
                    assertEquals(listOf<Throwable>(failure), e.suppressedExceptions)
                    assertEquals("WARN", log.lines.single { it.cause === failure }.level)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aReleaseThatReturnsLogsNothing() {
        val log = CapturedLog()
        var released = false
        releaseH2Stream(5, log, null) { released = true }
        assertEquals(true, released)
        assertEquals(emptyList(), log.lines)
    }
}
