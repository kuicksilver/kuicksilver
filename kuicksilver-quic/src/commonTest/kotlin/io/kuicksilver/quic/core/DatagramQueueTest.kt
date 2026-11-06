// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The received-DATAGRAM ring: made by the first datagram (P.5), oldest dropped when full, payloads handed out in order. */
class DatagramQueueTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun push(
        q: DatagramQueue,
        vararg bytes: Byte,
    ): Boolean {
        val b = PacketBuffer.of(bytes)
        try {
            return q.push(b, 0, bytes.size)
        } finally {
            b.close()
        }
    }

    private fun poll(q: DatagramQueue): ByteArray? {
        val into = ByteArray(2000)
        val n = q.poll(into, 0)
        return if (n < 0) null else into.copyOf(n)
    }

    @Test fun aConnectionThatReceivesNoDatagramHoldsNoRing() {
        val q = DatagramQueue(128)
        assertFalse(q.allocatedForTest, "no datagram, no ring")
        assertEquals(-1, q.poll(ByteArray(10), 0))
        assertFalse(q.allocatedForTest, "polling an empty queue makes none either")
        push(q, 1)
        assertTrue(q.allocatedForTest)
    }

    @Test fun aFullQueueDropsTheOldestAndKeepsTheOrder() {
        val q = DatagramQueue(2)
        assertFalse(push(q, 1))
        assertFalse(push(q, 2, 2))
        assertTrue(push(q, 3, 3, 3), "the third of two drops the oldest")
        assertEquals(2, q.size)
        assertContentEquals(byteArrayOf(2, 2), poll(q))
        assertContentEquals(byteArrayOf(3, 3, 3), poll(q))
        assertEquals(null, poll(q))
    }
}
