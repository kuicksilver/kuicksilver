// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.DatagramPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The loop side of the datagram send queue: bounds, Reject accounting, LatestWins replacement, eviction only when the network did not take the queue. */
@OptIn(ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
class DatagramSendQueueTest {
    private class Sink(
        var room: Int,
        override val maxPayload: Int = 1168,
    ) : DatagramPacketWriter {
        val out = ArrayList<ByteArray>()
        override val remaining: Int get() = room

        override fun write(
            data: ByteArray,
            offset: Int,
            length: Int,
            id: Long,
        ): Boolean {
            if (length >
                room
            ) {
                return false
            }
            out += data.copyOfRange(offset, offset + length)
            room -= length
            return true
        }
    }

    private fun fill(
        q: DatagramSendQueue,
        n: Int,
        size: Int = 1000,
        policy: DatagramPolicy = DatagramPolicy.DropOldest,
    ) {
        repeat(n) {
            q.offer(
                ByteArray(size) { b ->
                    (
                        it +
                            b
                    ).toByte()
                },
                policy,
            )
        }
    }

    @Test fun negative_datagramQueueCap() {
        val q = DatagramSendQueue(32, 1_048_576)
        fill(q, 1000)
        assertFalse(q.hasRoom(1000), "1000 offered: Reject callers see no room")
        assertEquals(32, q.count.load(), "the command channel keeps the newest 32 (runtime review I6)")
        assertTrue(q.applyCommands())
        fill(q, 1000)
        assertEquals(64, q.count.load(), "queue + commands stay within 2 x 32")
        assertFalse(q.applyCommands(), "the queue is full: the next command waits")
        assertTrue(q.isFull)
        assertTrue(q.hasPendingCommands)
        var rounds = 0
        while (q.hasPendingCommands) {
            q.evictForPending()
            q.applyCommands()
            rounds++
        } // the network never took anything: DropOldest evicts
        assertTrue(rounds >= 30)
        assertEquals(32, q.count.load())
        assertEquals(32_000L, q.bytes.load())
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        assertEquals(32, sink.out.size)
        assertEquals(
            999 and 0xff,
            sink.out.last()[0].toInt() and 0xff,
            "the newest 32 survive",
        )
        assertEquals(0, q.count.load())
        assertTrue(q.hasRoom(1000))
        assertTrue(q.isEmpty)
        val big = DatagramSendQueue(32, 10_000)
        fill(big, 20, 1000)
        big.applyCommands()
        while (big.hasPendingCommands) {
            big.evictForPending()
            big.applyCommands()
        }
        assertTrue(big.bytes.load() <= 10_000L && big.count.load() == 10, "the byte bound holds: ${big.count.load()} x 1000")
    }

    @Test fun latestWinsReplacesByKey() {
        val q = DatagramSendQueue(32, 1_048_576)
        q.offer(byteArrayOf(1, 1), DatagramPolicy.LatestWins("A"))
        q.offer(byteArrayOf(2, 1), DatagramPolicy.LatestWins("B"))
        q.offer(byteArrayOf(1, 2), DatagramPolicy.LatestWins("A"))
        q.applyCommands()
        assertEquals(2, q.count.load())
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        assertEquals(listOf(listOf<Byte>(2, 1), listOf<Byte>(1, 2)), sink.out.map { it.toList() }, "B, then the latest A")
        fill(q, 32, 10)
        q.applyCommands()
        q.offer(byteArrayOf(9), DatagramPolicy.LatestWins("A"))
        q.applyCommands()
        assertEquals(33, q.count.load(), "a new key over a full queue waits for the loop")
        assertTrue(q.hasPendingCommands)
    }

    @Test fun transmitStopsAtPacketRoom() {
        val q = DatagramSendQueue(32, 1_048_576)
        fill(q, 5, 400)
        q.applyCommands()
        val sink = Sink(1000)
        q.onTransmit(sink)
        assertEquals(2, sink.out.size, "two 400-byte datagrams fit 1000 bytes")
        assertEquals(3, q.count.load())
    }
}
