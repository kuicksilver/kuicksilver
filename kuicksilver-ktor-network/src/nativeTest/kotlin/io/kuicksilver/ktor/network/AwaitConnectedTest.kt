// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * The bounded connect wait (Windows can lose FD_CONNECT) over its seams: no sockets, virtual time. Real loopback connects
 * complete at once on macOS and Linux, so these paths are reached only here (review S3 of 4500e6a4).
 */
class AwaitConnectedTest {
    private class Refused(
        val errno: Int,
    ) : Exception("connect: $errno")

    private val inProgress = 36

    private suspend fun await(
        select: suspend () -> Unit,
        pendingError: () -> Int,
        connected: () -> Boolean,
        rechecks: (() -> Unit)? = null,
    ) = awaitConnectedWith(
        select = select,
        pendingError = pendingError,
        connected = connected,
        wouldBlock = { it == inProgress },
        failed = { throw Refused(it) },
        recheck = 20.milliseconds,
        undecidedLimit = 100.milliseconds,
        rechecks = rechecks,
    )

    /** The selector never reports: the recheck finds the socket connected (no error, a peer) on its third look. */
    @Test fun aConnectTheSelectorNeverReportsCompletesOnARecheck() =
        runTest {
            var looks = 0
            var rechecks = 0
            await({ awaitCancellation() }, { 0 }, { ++looks >= 3 }) { rechecks++ }
            assertEquals(3, rechecks)
        }

    /** The selector never reports: the recheck finds the refusal in SO_ERROR and the connect fails with it. */
    @Test fun negative_aRefusalTheSelectorNeverReportsFails() =
        runTest {
            val e = assertFailsWith<Refused> { await({ awaitCancellation() }, { 61 }, { false }) }
            assertEquals(61, e.errno)
        }

    /** "Not yet" is no verdict: the connect waits on until it has one. */
    @Test fun inProgressIsWaitedOut() =
        runTest {
            var looks = 0
            await({ awaitCancellation() }, { if (++looks < 3) inProgress else 0 }, { looks >= 3 })
            assertEquals(3, looks)
        }

    /** No error and no peer, for longer than the limit: the connect fails instead of waiting for ever. */
    @Test fun negative_anUndecidedConnectFailsAtItsLimit() =
        runTest {
            val e = assertFailsWith<IOException> { await({ awaitCancellation() }, { 0 }, { false }) }
            assertTrue("neither completed nor failed" in e.message.orEmpty(), "$e")
        }

    /**
     * The selector reported the connect but the socket has no error and no peer: no second report will come (FD_CONNECT is
     * posted once), so the connect fails at once, not after the limit.
     */
    @Test fun negative_aReportWithoutAPeerFailsAtOnce() =
        runTest {
            var looks = 0
            val e =
                assertFailsWith<IOException> {
                    await({}, {
                        looks++
                        0
                    }, { false })
                }
            assertTrue("reported done" in e.message.orEmpty(), "$e")
            assertEquals(1, looks, "it looked again")
        }

    /** A report with a peer: connected. */
    @Test fun aReportedConnectWithAPeerCompletes() =
        runTest {
            await({}, { 0 }, { true })
        }
}
