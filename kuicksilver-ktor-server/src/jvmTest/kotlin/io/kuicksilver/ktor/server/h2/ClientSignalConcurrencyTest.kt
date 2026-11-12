// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h2

import io.kuicksilver.quic.StreamPriority
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * [ClientSignal] under real threads: signals with interleaved orders (seq) from several threads. A reader that polls the
 * state the whole time never sees its order go down, and the state ends on the highest one.
 */
class ClientSignalConcurrencyTest {
    @Test fun observedOrderIsMonotonic() {
        repeat(50) { round ->
            val s = ClientSignal(StreamPriority.Default)
            val threads = 4
            val perThread = 500
            val barrier = CyclicBarrier(threads + 1)

            val done = AtomicBoolean(false)
            val fellBack = AtomicBoolean(false)
            val reader =
                thread {
                    barrier.await()
                    var last = -1L
                    while (!done.get()) {
                        val seq = s.state.value.seq
                        if (seq < last) fellBack.set(true)
                        last = seq
                    }
                }
            val writers =
                List(threads) { t ->
                    thread {
                        barrier.await()
                        for (i in 0 until perThread) {
                            val seq = (i * threads + t + 1).toLong()
                            s.signal((seq % 8).toInt(), seq % 2 == 0L, seq)
                        }
                    }
                }
            writers.forEach { it.join() }
            done.set(true)
            reader.join()
            assertTrue(!fellBack.get(), "round $round: the observed order went down")
            val max = (threads * perThread).toLong()
            assertEquals(max, s.state.value.seq)
            assertEquals(StreamPriority((max % 8).toInt(), max % 2 == 0L), s.flow.value)
        }
    }
}
