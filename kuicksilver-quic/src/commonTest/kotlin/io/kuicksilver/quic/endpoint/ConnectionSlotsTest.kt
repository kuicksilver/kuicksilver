// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.quic.core.AddressClass
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** The slots of `maxConnections` and `maxConnectionsPerIp`, alone and shared by a loop group. */
class ConnectionSlotsTest {
    private fun ip(n: Int) = AddressClass.IpKey(byteArrayOf(10, 0, 0, n.toByte()))

    private fun limits(slots: ConnectionSlots) {
        assertEquals(0, slots.acquire(ip(1), 3, 2))
        assertEquals(1, slots.acquire(ip(1), 3, 2))
        assertEquals(-1, slots.acquire(ip(1), 3, 2), "the address is full")
        assertEquals(0, slots.acquire(ip(2), 3, 2))
        assertEquals(-1, slots.acquire(ip(3), 3, 2), "the endpoint is full")
        assertEquals(3, slots.total)
        slots.release(ip(1))
        assertEquals(1, slots.acquire(ip(1), 3, 2), "a released slot is taken again")
        slots.acquireUnchecked()
        assertEquals(4, slots.total, "a client connection counts past the limit")
        slots.release(null)
        slots.release(ip(1))
        slots.release(ip(1))
        slots.release(ip(2))
        assertEquals(0, slots.total)
        assertEquals(0, slots.addresses, "no entry is left once every connection is gone")
        assertEquals(0, slots.acquire(ip(3), 3, null), "null: no per-address limit")
    }

    @Test fun localLimits() = limits(ConnectionSlots.Local())

    @Test fun sharedLimits() = limits(ConnectionSlots.Shared(Random(1)))

    /**
     * Eight threads take and give back slots of four addresses at once: no address ever holds more than its limit, the total
     * never passes its own, and everything is given back.
     */
    @Test fun negative_sharedLimitsHoldUnderContention() =
        runBlocking {
            withTimeout(30.seconds) {
                val slots = ConnectionSlots.Shared(Random(2))
                val held = Array(4) { AtomicInt(0) }
                val total = AtomicInt(0)
                val worst = AtomicInt(0)
                (0 until 8)
                    .map { w ->
                        async(Dispatchers.Default) {
                            val r = Random(w)
                            repeat(20_000) {
                                val k = r.nextInt(4)
                                if (slots.acquire(ip(k), 6, 3) >= 0) {
                                    val h = held[k].incrementAndFetch()
                                    val t = total.incrementAndFetch()
                                    if (h > 3 || t > 6) worst.incrementAndFetch()
                                    held[k].decrementAndFetch()
                                    total.decrementAndFetch()
                                    slots.release(ip(k))
                                }
                            }
                        }
                    }.awaitAll()
                assertEquals(0, worst.load(), "a limit was passed")
                assertEquals(0, slots.total)
                assertEquals(0, slots.addresses)
            }
        }
}
