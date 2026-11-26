// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramPacketWriter
import io.kuicksilver.quic.DatagramPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertSame
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

    /** A datagram of [size] bytes of [group], numbered [n]: its first two bytes. */
    private fun dg(
        group: Int,
        n: Int,
        size: Int = 1000,
    ) = ByteArray(size).also {
        it[0] = group.toByte()
        it[1] = n.toByte()
    }

    private fun Sink.tags() = out.map { it[0].toInt() to it[1].toInt() }

    /**
     * The flows of one urgency take turns by deficit round robin over bytes ([DatagramSendQueue.QUANTUM] a turn), whatever
     * order they were queued in; a more urgent flow first.
     */
    @Test fun groupsOfOneUrgencyTakeTurns() {
        val q = DatagramSendQueue(32, 1_048_576)
        repeat(4) { q.offer(dg(4, it), DatagramPolicy.DropOldest, 3, 4) }
        repeat(2) { q.offer(dg(8, it), DatagramPolicy.DropOldest, 3, 8) }
        q.offer(dg(12, 0), DatagramPolicy.DropOldest, 1, 12)
        q.applyCommands()
        val urgent = Sink(Int.MAX_VALUE)
        q.onTransmit(urgent)
        assertEquals(listOf(12 to 0), urgent.tags(), "the more urgent flow first")
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        assertEquals(listOf(4 to 0, 8 to 0, 4 to 1, 8 to 1, 4 to 2, 4 to 3), sink.tags())
        assertFalse(q.hasPending())
    }

    /** The turns count bytes: a group of large datagrams gets the same share as one of small datagrams, not 12 times it. */
    @Test fun negative_aGroupOfLargeDatagramsGetsNoLargerShare() {
        val q = DatagramSendQueue(64, 1_048_576)
        repeat(4) { q.offer(dg(4, it, 1100), DatagramPolicy.DropOldest, 3, 4) }
        repeat(44) { q.offer(dg(8, it, 100), DatagramPolicy.DropOldest, 3, 8) }
        q.applyCommands()
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        // the first 4600 bytes: within one quantum of each other (a datagram-count turn gave group 4 eleven times 8's bytes)
        var sent = 0
        val byGroup = HashMap<Int, Int>()
        for (d in sink.out) {
            if (sent >= 4600) break
            byGroup[d[0].toInt()] = (byGroup[d[0].toInt()] ?: 0) + d.size
            sent += d.size
        }
        assertEquals(mapOf(4 to 2200, 8 to 2400), byGroup)
    }

    /**
     * A flow's burst evicts its own datagrams (draft-ietf-webtrans-http3-16 sections 3.4 and 8, unchanged in -17 per the
     * project's notes): session 4 holds three datagrams, session 8 floods a full queue, and 4's three stay; a session with
     * nothing queued takes room from the one that holds the most bytes. Before, all sessions shared one DropOldest FIFO, so
     * 8's burst pushed 4's datagrams out first (they were the oldest).
     */
    @Test fun negative_aBurstEvictsOnlyItsOwnGroupsDatagrams() {
        val q = DatagramSendQueue(8, 1_048_576)
        repeat(3) { q.offer(dg(4, it), DatagramPolicy.DropOldest, 3, 4) }
        q.applyCommands()
        repeat(40) {
            q.offer(dg(8, it), DatagramPolicy.DropOldest, 3, 8)
            q.applyCommands(evict = true)
        }
        assertEquals(3, q.queuedForTest(4), "the other session's datagrams stay")
        assertEquals(5, q.queuedForTest(8), "the bursting session holds the rest of the queue, its newest")
        q.offer(dg(12, 0), DatagramPolicy.DropOldest, 3, 12)
        q.applyCommands(evict = true)
        assertEquals(listOf(3, 4, 1), listOf(4L, 8L, 12L).map { q.queuedForTest(it) })
    }

    /**
     * Admission is per group too: a caller that floods faster than the loop drains drops its own group's oldest commands,
     * never another group's. Before, one bounded DROP_OLDEST channel in front of the queue let group 1's flood push group 2's
     * command out before the loop saw it (review 4: 3 of 50 got through); then 64 hashed rings let two groups share one.
     */
    @Test fun negative_aFloodInAdmissionDropsOnlyItsOwnCommands() {
        val n = 8
        val q = DatagramSendQueue(n, 1_048_576)
        q.offer(dg(2, 0), DatagramPolicy.DropOldest, 3, 2)
        repeat(10 * n) { q.offer(dg(1, it), DatagramPolicy.DropOldest, 3, 1) }
        assertEquals(n + 1, q.count.load(), "each group's admission holds its own: group 1's newest $n and group 2's one")
        q.applyCommands()
        assertEquals(1, q.queuedForTest(2), "group 2's datagram got through the flood")
        assertEquals(n - 1, q.queuedForTest(1))
    }

    /** Every group gets an admission of its own, however many there are: no two ever share one. */
    @Test fun negative_manyGroupsNeverShareAdmission() {
        val n = 4
        val q = DatagramSendQueue(n, 1_048_576)
        val groups = 1000
        for (g in 1..groups) q.startGroup(g * 4L)
        assertEquals(groups, q.admissionCountForTest)
        val seen = HashSet<Any>()
        for (g in 1..groups) assertTrue(seen.add(q.admissionForTest(g * 4L)!!), "group ${g * 4} has its own admission")
        for (g in 1..groups) assertSame(q.admissionForTest(g * 4L), q.admissionForTest(g * 4L))
        // one datagram each, then every group floods but group 4: each keeps its own newest n, group 4 its one
        for (g in 1..groups) q.offer(dg(g, 0, 10), DatagramPolicy.DropOldest, 3, g * 4L)
        for (g in 2..groups) repeat(3 * n) { q.offer(dg(g, it, 10), DatagramPolicy.DropOldest, 3, g * 4L) }
        assertEquals(1 + (groups - 1) * n, q.count.load(), "no flood took another group's command")
        q.offer(dg(0, 0, 10), DatagramPolicy.DropOldest, 3) // of no group: the shared admission
        assertEquals(2 + (groups - 1) * n, q.count.load())
    }

    /**
     * The reviewer's interleaving, replayed on channels: a producer that looked its group's admission up when the group
     * ended sends to a closed channel and goes to a new admission; the ended one's commands are still drained. The drainer
     * never waits for a producer: it returns with nothing admitted left (before, a producer lapped by its own ring between
     * its ticket and its write left a slot that was never written, and the drainer spun on it).
     */
    @Test fun negative_aProducerRacingTheGroupsEndStallsNothing() {
        val n = 4
        val q = DatagramSendQueue(n, 1_048_576)
        q.startGroup(7)
        val before = q.admissionForTest(7)!!
        repeat(n + 2) { q.offer(dg(7, it, 10), DatagramPolicy.DropOldest, 3, 7) } // lapped: its own oldest two go
        q.endGroup(7)
        assertTrue(before.channel.trySend(DatagramSendQueue.Cmd(dg(7, 99, 10), DatagramPolicy.DropOldest, 3, 7)).isFailure)
        q.offer(dg(7, 9, 10), DatagramPolicy.DropOldest, 3, 7) // the late producer: a new admission
        assertNotSame(before, q.admissionForTest(7))
        var flushes = 0
        assertFalse(q.drain { flushes++ }, "nothing admitted is left")
        assertFalse(q.hasPendingCommands)
        assertEquals(n, q.queuedForTest(7))
        assertEquals(n, q.count.load())
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        // the ended admission's newest four came first, the late one last; the full queue dropped the group's oldest
        assertEquals(listOf(3, 4, 5, 9), sink.tags().map { it.second }, "order kept within the group")
        assertEquals(0, q.count.load())
        assertTrue(flushes >= 1)
        assertEquals(0, q.groupCountForTest, "the ended group left no state")
    }

    /**
     * The drainer returns when the network takes nothing and a command does not fit by bytes while the queue is not full
     * (before, that case yield-spun on the endpoint loop): the eviction rules decide at once.
     */
    @Test fun negative_aCommandThatDoesNotFitByBytesIsDecidedAtOnce() {
        val q = DatagramSendQueue(32, 1000)
        q.offer(dg(4, 0, 900), DatagramPolicy.DropOldest, 3, 4)
        repeat(5) { q.offer(dg(8 + it, 0, 200), DatagramPolicy.DropOldest, 3, 8L + it) }
        var flushes = 0
        assertFalse(q.drain { flushes++ })
        assertFalse(q.hasPendingCommands)
        assertTrue(flushes <= 2, "$flushes flushes")
        assertTrue(q.bytes.load() <= 1000L)
    }

    /**
     * A drain pass takes no more than was admitted when it started, however fast senders keep admitting (here: every flush
     * admits a burst of each group): it returns, saying more is admitted, and the endpoint loop runs its other work before
     * the next pass. Before, one drain ran as long as senders kept up (review 6: 94 and 284 s of a held loop).
     */
    @Test fun negative_aDrainPassIsBoundedByWhatWasAdmitted() {
        val n = 8
        val q = DatagramSendQueue(n, 1_048_576)
        for (g in 1..3) q.startGroup(g * 4L)

        fun burst() {
            for (g in 1..3) repeat(n) { q.offer(dg(g, it, 10), DatagramPolicy.DropOldest, 3, g * 4L) }
        }
        burst()
        var flushes = 0
        val more =
            q.drain {
                flushes++
                burst() // senders on other threads keep up with the loop
            }
        assertTrue(more, "senders kept admitting: the caller yields and comes back")
        assertTrue(flushes <= 2, "one pass: $flushes flushes")
        assertTrue(q.admittedNow() > 0)
        // the senders stop: the next pass takes the rest
        var passes = 0
        while (q.drain {}) passes++
        assertTrue(passes <= 2)
        assertFalse(q.hasPendingCommands)
    }

    /**
     * A group that ends while a datagram of its is still in admission leaves no state once that datagram left (review 6:
     * it came back as a fresh group, never marked ended).
     */
    @Test fun negative_anEndedGroupsLateAdmissionLeavesNoGroupBehind() {
        val q = DatagramSendQueue(8, 1_048_576)
        q.startGroup(4)
        q.offer(dg(4, 0, 10), DatagramPolicy.DropOldest, 3, 4)
        q.endGroup(4) // its datagram is still in admission
        q.applyCommands()
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        assertEquals(1, sink.out.size)
        assertEquals(0, q.groupCountForTest, "an ended group's state lingers")
        q.applyCommands() // its drained admission goes too
        assertEquals(0, q.admissionCountForTest)
        assertEquals(0, q.count.load())
    }

    /** A group whose start was reported is never swept while idle, however many groups there are; made ones are. */
    @Test fun startedGroupsAreNeverSwept() {
        val q = DatagramSendQueue(8, 1_048_576)
        val live = 3000
        for (g in 1..live) q.startGroup(g * 4L)
        val first = q.admissionForTest(4)!!
        val sink = Sink(Int.MAX_VALUE)
        for (g in 1..live) {
            q.offer(dg(g, 0, 10), DatagramPolicy.DropOldest, 3, g * 4L)
            q.applyCommands()
            q.onTransmit(sink)
        }
        assertSame(first, q.admissionForTest(4), "a started, idle group keeps its admission")
        assertEquals(live, q.admissionCountForTest)
        assertEquals(live, q.groupCountForTest)
        // groups made at their first datagram (never started) are swept when idle
        for (g in 1..2000) {
            q.offer(dg(g, 0, 10), DatagramPolicy.DropOldest, 3, (live + g) * 4L + 1)
            q.applyCommands()
            q.onTransmit(sink)
        }
        assertTrue(q.admissionCountForTest < live + 2000, "idle made groups were swept: ${q.admissionCountForTest}")
        assertSame(first, q.admissionForTest(4))
    }

    /** Eviction in the sender's own group never drops a more urgent queued datagram for a less urgent new one. */
    @Test fun negative_evictionKeepsTheGroupsMoreUrgentDatagrams() {
        val q = DatagramSendQueue(2, 1_048_576)
        q.offer(dg(4, 0), DatagramPolicy.DropOldest, 0, 4)
        q.offer(dg(4, 1), DatagramPolicy.DropOldest, 0, 4)
        q.applyCommands()
        q.offer(dg(4, 2), DatagramPolicy.DropOldest, 5, 4)
        q.applyCommands(evict = true)
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        assertEquals(listOf(4 to 0, 4 to 1), sink.tags(), "the u=5 one is dropped, not a u=0 one")
        assertEquals(0, q.count.load())
        // one of the same urgency evicts its group's oldest
        q.offer(dg(4, 3), DatagramPolicy.DropOldest, 0, 4)
        q.offer(dg(4, 4), DatagramPolicy.DropOldest, 0, 4)
        q.offer(dg(4, 5), DatagramPolicy.DropOldest, 0, 4)
        q.applyCommands(evict = true)
        val again = Sink(Int.MAX_VALUE)
        q.onTransmit(again)
        assertEquals(listOf(4 to 4, 4 to 5), again.tags())
    }

    /** LatestWins replaces a queued datagram of its own group only. */
    @Test fun negative_latestWinsReplacesOnlyWithinItsGroup() {
        val q = DatagramSendQueue(32, 1_048_576)
        q.offer(dg(4, 0), DatagramPolicy.LatestWins("k"), 3, 4)
        q.offer(dg(8, 0), DatagramPolicy.LatestWins("k"), 3, 8)
        q.offer(dg(4, 1), DatagramPolicy.LatestWins("k"), 3, 4)
        q.applyCommands()
        val sink = Sink(Int.MAX_VALUE)
        q.onTransmit(sink)
        assertEquals(setOf(4 to 1, 8 to 0), sink.tags().toSet())
        assertEquals(2, sink.out.size)
    }

    /** A group's state stays while it is in use and goes once its stream ended and its last datagram left. */
    @Test fun endedGroupsLeaveNoState() {
        val q = DatagramSendQueue(32, 1_048_576)
        q.offer(dg(4, 0), DatagramPolicy.DropOldest, 3, 4)
        q.applyCommands()
        q.onTransmit(Sink(Int.MAX_VALUE))
        assertEquals(1, q.groupCountForTest, "kept for its next datagram: no allocation per datagram")
        q.offer(dg(4, 1), DatagramPolicy.DropOldest, 3, 4)
        q.applyCommands()
        q.endGroup(4)
        assertEquals(1, q.groupCountForTest, "a datagram still queued")
        q.onTransmit(Sink(Int.MAX_VALUE))
        assertEquals(0, q.groupCountForTest)
    }

    /**
     * One FIFO per urgency: a u=0 datagram queued behind a u=7 one does not wait for it (nor for the u=1..6 streams the u=7
     * one lets go first); order within an urgency is kept, and one transmit writes a single urgency.
     */
    @Test fun negative_urgentDatagramDoesNotWaitBehindALessUrgentOne() {
        val q = DatagramSendQueue(32, 1_048_576)
        q.offer(byteArrayOf(7), DatagramPolicy.DropOldest, 7)
        q.offer(byteArrayOf(0, 1), DatagramPolicy.DropOldest, 0)
        q.offer(byteArrayOf(0, 2), DatagramPolicy.DropOldest, 0)
        q.applyCommands()
        assertEquals(0, q.nextUrgency())
        val first = Sink(1000)
        q.onTransmit(first)
        assertEquals(listOf(listOf<Byte>(0, 1), listOf<Byte>(0, 2)), first.out.map { it.toList() })
        assertEquals(7, q.nextUrgency())
        val second = Sink(1000)
        q.onTransmit(second)
        assertEquals(listOf(listOf<Byte>(7)), second.out.map { it.toList() })
        assertEquals(-1, q.nextUrgency())
        assertFalse(q.hasPending())
    }

    /**
     * LatestWins replaces the queued datagram of its key whatever the urgency of either: the old u=7 one is gone, its FIFO
     * empty, the counters exact, and only the new u=0 one is sent.
     */
    @Test fun negative_latestWinsReplacesAcrossUrgencies() {
        val q = DatagramSendQueue(32, 1_048_576)
        q.offer(ByteArray(100) { 7 }, DatagramPolicy.LatestWins("k"), 7)
        q.applyCommands()
        assertEquals(7, q.nextUrgency())
        q.offer(ByteArray(10) { 0 }, DatagramPolicy.LatestWins("k"), 0)
        q.applyCommands()
        assertEquals(1, q.count.load(), "one datagram of key k is queued")
        assertEquals(10L, q.bytes.load())
        assertEquals(0, q.nextUrgency())
        val out = Sink(1000)
        q.onTransmit(out)
        assertEquals(listOf(List<Byte>(10) { 0 }), out.out.map { it.toList() })
        // nothing left at u=7: its FIFO's bit is clear
        assertEquals(-1, q.nextUrgency())
        assertFalse(q.hasPending())
        assertTrue(q.isEmpty)
        assertEquals(0, q.count.load())
        assertEquals(0L, q.bytes.load())
    }

    /** Eviction under DropOldest drops the group's least urgent oldest datagram, not the head of the most urgent queue. */
    @Test fun evictionDropsTheOldestOfAllUrgencies() {
        val q = DatagramSendQueue(2, 1_048_576)
        q.offer(byteArrayOf(5), DatagramPolicy.DropOldest, 5)
        q.offer(byteArrayOf(1), DatagramPolicy.DropOldest, 1)
        q.applyCommands()
        q.offer(byteArrayOf(9), DatagramPolicy.DropOldest, 1)
        q.applyCommands()
        q.evictForPending()
        val out = Sink(1000)
        q.onTransmit(out)
        assertEquals(listOf(listOf<Byte>(1), listOf<Byte>(9)), out.out.map { it.toList() })
        assertFalse(q.hasPending(), "the u=5 datagram, the oldest, was evicted")
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
