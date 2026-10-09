// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.EndpointCore
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.TimeMark
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** The loop's timer heap against a brute-force model: after any mix of updates and removals the head is the earliest deadline. */
class TimerHeapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun headIsAlwaysTheEarliestDeadline() {
        val ep = EndpointCore(QuicEndpointConfig.Builder().apply { crypto = NullCryptoProvider }.build(), Random(2))
        val cfg = QuicClientConfig.Builder(CoreFixtures.client()).build()
        val cores = (0 until 40).map { ep.connect(cfg, InetSocketAddress("10.0.0.1", 1000 + it), TimeMark(1_000_000_000L)) }
        val heap = TimerHeap()
        val model = HashMap<Int, Long>()
        val r = Random(7)
        repeat(5000) {
            val i = r.nextInt(cores.size)
            when (r.nextInt(4)) {
                0 -> {
                    heap.remove(cores[i])
                    model.remove(i)
                }

                else -> {
                    val d = 1_000_000_000L + r.nextLong(0, 1_000_000)
                    heap.update(cores[i], TimeMark(d))
                    model[i] = d
                }
            }
            val expected = model.values.minOrNull()
            if (expected == null) assertNull(heap.peek()) else assertEquals(expected, heap.peek()!!.heapDeadline.nanos, "step $it")
        }
        // drain in order
        var last = Long.MIN_VALUE
        while (true) {
            val c =
                heap.peek() ?: break
            assertEquals(true, c.heapDeadline.nanos >= last, "drain order")
            last = c.heapDeadline.nanos
            heap.remove(c)
        }
        assertEquals(true, heap.isEmpty)
    }
}
