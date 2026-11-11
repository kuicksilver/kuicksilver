// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource

/**
 * What the accept loop hands a connection's coroutine (the accepted socket, the TLS session its handshake made) is released
 * however that coroutine ends, also when it never runs or a timeout drops the session.
 */
class ConnectionHandOverTest {
    /**
     * A handshake that completes as the request-head deadline fires: kotlinx's `withTimeoutOrNull` answers null and drops
     * the result, whose native TLS session nobody would close. The block here has suspended once (as a handshake does;
     * a block that never suspends keeps its result) and finishes without suspending again after the deadline fired on
     * another thread, which is exactly that window.
     */
    @Test fun aResultMadeAsTheDeadlineFiresIsReleased(): Unit =
        runBlocking {
            val released = mutableListOf<String>()
            val result =
                withContext(Dispatchers.Default) {
                    withTimeoutOrRelease(50.milliseconds, { released += it }) {
                        yield()
                        val start = TimeSource.Monotonic.markNow()
                        @Suppress("ControlFlowWithEmptyBody")
                        while (start.elapsedNow() < 300.milliseconds) {
                        }
                        "session"
                    }
                }
            assertNull(result)
            assertEquals(listOf("session"), released)
        }

    @Test fun aResultInTimeIsReturnedNotReleased(): Unit =
        runBlocking {
            val released = mutableListOf<String>()
            assertEquals("session", withTimeoutOrRelease(5000.milliseconds, { released += it }) { "session" })
            assertTrue(released.isEmpty())
        }

    /**
     * A stop between `accept()` and the connection's launch: the scope is cancelled, and a plain `launch` never ran its
     * body (nor its `finally`), so the accepted socket and its `maxTcpConnections` slot stayed taken.
     */
    @Test fun aLaunchOnACancelledScopeStillReleases(): Unit =
        runBlocking {
            val scope = CoroutineScope(Job().apply { cancel() })
            var released = false
            var ran = false
            scope.launchOrElse(onCancelled = { released = true }) { ran = true }.join()
            assertTrue(released)
            assertFalse(ran)
        }

    @Test fun aLaunchOnALiveScopeRunsTheBlock(): Unit =
        runBlocking {
            var released = false
            var ran = false
            launchOrElse(onCancelled = { released = true }) { ran = true }.join()
            assertTrue(ran)
            assertFalse(released)
        }
}
