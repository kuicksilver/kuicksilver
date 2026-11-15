// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A capsule write that [WtSessionImpl.closeTimeout] bounds and that is done as the deadline fires (the timeout lands on
 * another thread after the write returned, before the deadline's scope completed) counts as written: no RESET_STREAM
 * after a close capsule and FIN, no failed drain() for a WT_DRAIN_SESSION that went out.
 */
class WtCloseDeadlineRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Returns only once the deadline cancelled the calling block, without suspending after its first resumption. */
    private suspend fun returnAsTheDeadlineFires() {
        yield() // the block completes through a resumption, as a real write does
        val job = currentCoroutineContext().job
        while (!job.isCancelled) Thread.onSpinWait()
    }

    @Test fun negative_aDrainWrittenAsTheDeadlineFiresIsNotReportedUnwritten() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val c = client as WtSessionImpl
                c.closeTimeout = 50.milliseconds
                c.closeWrittenForTest = { returnAsTheDeadlineFires() }
                c.drain() // threw WebTransportException.Timeout and reset the session
                assertFalse(c.closed.isCompleted, "a drain that was written leaves the session open")
                withTimeout(5.seconds) { server.drainRequested.first { it } }
            }
        }

    @Test fun negative_aCloseWrittenAsTheDeadlineFiresIsNotReset() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = sessions(p)
                val c = client as WtSessionImpl
                c.closeTimeout = 50.milliseconds
                c.closeWrittenForTest = { returnAsTheDeadlineFires() }
                c.close(7, "raced")
                assertEquals(0, c.connectResetsForTest, "the close capsule and FIN went out: no RESET_STREAM may discard them")
                val seen = withTimeout(5.seconds) { server.closed.await() }
                assertEquals(7L, seen.code)
            }
        }
}
