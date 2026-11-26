// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.runtime.ConnectionRuntime
import io.kuicksilver.quic.trySendDatagram
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Datagram senders that flood from other threads do not hold the endpoint loop: a hop onto the loop, taken every 50 ms for
 * 3 s, answers within [BOUND_MS] (generous for a loaded CI machine). Before, one drain ran as long as the senders kept
 * up: the loop answered after 94 s and 284 s (review 6 of 2026-11-27), and every connection on it starved (ACKs, timers).
 */
class DatagramDrainerLatencyJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun worstLoopLatencyMs(
        threads: Int,
        grouped: Boolean,
    ): Long =
        runBlocking {
            ApiPair.open().use { p ->
                val (c, s) = p.connect()
                val stop = AtomicBoolean(false)
                val floods =
                    List(threads) { k ->
                        thread {
                            val a = ByteArray(200)
                            while (!stop.get()) {
                                if (grouped) {
                                    c.trySendDatagram(a, DatagramPolicy.DropOldest, StreamPriority.Default, 1L + k)
                                } else {
                                    c.trySendDatagram(a, DatagramPolicy.DropOldest)
                                }
                            }
                        }
                    }
                var worst = 0L
                try {
                    val end = System.nanoTime() + 3_000_000_000L
                    while (System.nanoTime() < end) {
                        val t0 = System.nanoTime()
                        val ok = withTimeoutOrNull(10.seconds) { withContext((c as ConnectionRuntime).loopDispatcherForTest) { } }
                        worst = maxOf(worst, if (ok == null) Long.MAX_VALUE else (System.nanoTime() - t0) / 1_000_000)
                        delay(50) // a probe every 50 ms against the flood: the real loop on the real clock is what is measured
                    }
                } finally {
                    stop.set(true)
                    floods.forEach { it.join() }
                }
                c.close()
                s.close()
                worst
            }
        }

    @Test fun negative_fourUngroupedFloodersDoNotHoldTheLoop() =
        worstLoopLatencyMs(4, grouped = false).let { assertTrue(it < BOUND_MS, "the loop answered after $it ms") }

    @Test fun negative_twoGroupedFloodersDoNotHoldTheLoop() =
        worstLoopLatencyMs(2, grouped = true).let { assertTrue(it < BOUND_MS, "the loop answered after $it ms") }

    @Test fun negative_fourGroupedFloodersDoNotHoldTheLoop() =
        worstLoopLatencyMs(4, grouped = true).let { assertTrue(it < BOUND_MS, "the loop answered after $it ms") }

    private companion object {
        const val BOUND_MS = 500L
    }
}
