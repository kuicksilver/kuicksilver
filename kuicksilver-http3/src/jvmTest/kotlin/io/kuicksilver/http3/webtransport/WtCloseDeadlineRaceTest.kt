// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A capsule write that [WtSessionImpl.closeTimeout] bounds and that is done as the deadline fires (the timeout lands on
 * another thread after the write returned, before the deadline's scope completed) counts as written: no RESET_STREAM
 * after a close capsule and FIN, no failed drain() for a WT_DRAIN_SESSION that went out. The write before the hook must end
 * within the deadline for the race to happen: a session whose hook was not reached in time does not count, and the next
 * one gets the deadline doubled.
 */
class WtCloseDeadlineRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Volatile private var reached = false

    /** Returns only once the deadline cancelled the calling block, without suspending after its first resumption. */
    private suspend fun returnAsTheDeadlineFires() {
        yield() // the block completes through a resumption, as a real write does; throws when the deadline already fired
        reached = true
        val job = currentCoroutineContext().job
        while (!job.isCancelled) Thread.onSpinWait()
    }

    /** Runs [attempt] on new sessions of one pair, the deadline doubled from 50 ms, until one reached the race. */
    private suspend fun CoroutineScope.raced(
        p: H3Pair,
        attempt: suspend (client: WtSessionImpl, server: WebTransportSession) -> Unit,
    ) {
        var d = 50.milliseconds
        repeat(8) {
            val (client, server) = sessions(p)
            val c = client as WtSessionImpl
            reached = false
            c.closeTimeout = d
            c.closeWrittenForTest = { returnAsTheDeadlineFires() }
            val outcome = runCatching { attempt(c, server) }
            if (reached) return outcome.getOrThrow()
            runCatching { c.close(0, "") }
            d *= 2
        }
        fail("the capsule write never ended within ${d / 2}")
    }

    @Test fun negative_aDrainWrittenAsTheDeadlineFiresIsNotReportedUnwritten() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                raced(p) { c, server ->
                    c.drain() // threw WebTransportException.Timeout and reset the session
                    assertFalse(c.closed.isCompleted, "a drain that was written leaves the session open")
                    withTimeout(5.seconds) { server.drainRequested.first { it } }
                }
            }
        }

    @Test fun negative_aCloseWrittenAsTheDeadlineFiresIsNotReset() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                raced(p) { c, server ->
                    c.close(7, "raced")
                    assertEquals(0, c.connectResetsForTest, "the close capsule and FIN went out: no RESET_STREAM may discard them")
                    val seen = withTimeout(5.seconds) { server.closed.await() }
                    assertEquals(7L, seen.code)
                }
            }
        }
}
