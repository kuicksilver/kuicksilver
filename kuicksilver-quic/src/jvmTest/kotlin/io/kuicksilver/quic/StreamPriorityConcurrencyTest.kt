// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.ApiPair
import io.kuicksilver.quic.runtime.StreamRuntime
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CyclicBarrier
import kotlin.concurrent.thread
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * [QuicStream.priority] set from several threads at once: once the loop has run what they queued, the scheduler sends the
 * stream with the priority the property reads. The setter used to hand its own value to the loop, so two setters whose
 * hand-overs ran in the other order than their writes left the scheduler on the older value.
 */
class StreamPriorityConcurrencyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun concurrentSettersEndOnTheLastValue() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, _) = p.connect()
                    val st = c.openBidi() as StreamRuntime
                    val threads = 4
                    repeat(200) { round ->
                        val barrier = CyclicBarrier(threads)
                        List(threads) { t ->
                            thread {
                                barrier.await()
                                st.priority = StreamPriority((round + t) % 8, t % 2 == 0)
                            }
                        }.forEach { it.join() }
                        // every update the setters queued runs before this block on the loop
                        val inCore = withContext(st.loop.dispatcher) { st.conn.core.priorityForTest(st.id) }
                        assertEquals(st.priority, inCore, "round $round")
                    }
                    c.close()
                }
            }
        }
}
