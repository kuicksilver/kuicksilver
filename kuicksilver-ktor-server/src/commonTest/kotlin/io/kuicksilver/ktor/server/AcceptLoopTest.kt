// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The TCP accept loop under failing `accept()` calls (EMFILE, ENFILE, ENOBUFS), on virtual time. */
class AcceptLoopTest {
    /** Ends a fake accept source; also stops a loop that would otherwise spin forever. */
    private class Stop : RuntimeException()

    /**
     * Consecutive accept failures wait 5 ms, doubling up to 1 s, and a successful accept resets the pause (Go
     * net/http `Server.Serve`). Before, the loop retried at once: with the descriptor table full it spun at 100 % CPU.
     */
    @Test fun negative_acceptFailuresBackOff() =
        runTest {
            val script = List(12) { false } + true + List(3) { false } // false: the accept fails
            val calls = ArrayList<Long>()
            val served = ArrayList<Long>()
            assertFailsWith<Stop> {
                acceptLoop(
                    accept = {
                        calls += currentTime
                        if (calls.size > script.size || calls.size > 10_000) throw Stop()
                        if (script[calls.size - 1]) "client" else throw IOException("Too many open files")
                    },
                    isClosed = { false },
                    onError = { _, _ -> },
                ) { served += currentTime }
            }
            val gaps = calls.zipWithNext { a, b -> b - a }
            assertEquals(
                listOf(5L, 10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000, 1000) + listOf(0L, 5, 10, 20),
                gaps,
                "pauses between accept calls (ms)",
            )
            assertEquals(listOf(calls[12]), served)
        }

    /** The pause is reported with the failure, so the engine can log it. */
    @Test fun failureIsReportedWithItsPause() =
        runTest {
            val reported = ArrayList<Pair<String?, Long>>()
            var n = 0
            assertFailsWith<Stop> {
                acceptLoop<String>(
                    accept = { if (++n > 3) throw Stop() else throw IOException("EMFILE $n") },
                    isClosed = { false },
                    onError = { e, pause -> reported += e.message to pause.inWholeMilliseconds },
                ) {}
            }
            assertEquals(listOf<Pair<String?, Long>>("EMFILE 1" to 5L, "EMFILE 2" to 10L, "EMFILE 3" to 20L), reported)
        }

    /** An accept that fails because the listening socket was closed ends the loop at once with that failure. */
    @Test fun closedSocketEndsTheLoopAtOnce() =
        runTest {
            var n = 0
            val e =
                assertFailsWith<IOException> {
                    acceptLoop<String>(
                        accept = {
                            if (++n > 10_000) throw Stop()
                            throw IOException("closed")
                        },
                        isClosed = { true },
                        onError = { _, _ -> },
                    ) {}
                }
            assertEquals("closed", e.message)
            assertEquals(1, n)
            assertEquals(0, currentTime)
        }

    /** Cancelling the loop while it waits between failed accepts ends it at once. */
    @Test fun cancellationDuringTheBackoffEndsTheLoop() =
        runTest {
            var n = 0
            val job =
                launch {
                    acceptLoop<String>(
                        accept = {
                            if (++n > 10_000) throw Stop()
                            throw IOException("EMFILE")
                        },
                        isClosed = { false },
                        onError = { _, _ -> },
                    ) {}
                }
            advanceTimeBy(2_500) // 5 + 10 + … + 640 = 1275 ms, then 1 s pauses: inside the second 1 s pause
            val before = n
            job.cancel()
            runCurrent()
            assertTrue(job.isCompleted)
            assertEquals(before, n, "accept was called after the cancellation")
            assertEquals(2_500, currentTime)
        }
}
