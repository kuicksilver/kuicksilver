// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.forAllSeeded
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The acknowledged ranges [PacketNumberSpace] keeps for persistent congestion (RFC 9002 section 7.6.2: "none of the packets sent
 * between the send times of these two packets are acknowledged"). Property: [PacketNumberSpace.anyAckedBetween] never answers
 * false when a packet number strictly between the two was acknowledged (a miss would declare persistent congestion wrongly), and
 * answers exactly while the acknowledged numbers form at most [ACKED_KEEP] ranges (beyond that it may only err towards true).
 */
class PacketNumberSpaceTest {
    @Test fun ackedRangesAnswerExactlyWithinCapacityAndConservativelyBeyond() {
        forAllSeeded(300, seed = 9002) { rnd, _ ->
            val sp = PacketNumberSpace(SpaceId.Application)
            val acked = BooleanArray(UNIVERSE)
            val steps = rnd.nextInt(1, 60)
            var overflowed = false // more ranges than ACKED_KEEP at some point: answers may err towards true from then on
            var floor = 0 // pruneAckedBelow(floor): only questions about numbers at or above it are asked (`pruneAcked`)
            repeat(steps) {
                if (rnd.nextInt(8) == 0) {
                    floor = rnd.nextInt(floor, UNIVERSE / 2 + floor / 2)
                    sp.pruneAckedBelow(floor.toLong())
                } else {
                    val lo = rnd.nextLong(floor.toLong(), UNIVERSE.toLong())
                    val hi = minOf(UNIVERSE - 1L, lo + rnd.nextLong(0, 6))
                    sp.recordAcked(lo, hi)
                    for (x in lo..hi) acked[x.toInt()] = true
                }
                overflowed = overflowed || rangesOf(acked).count { it.last >= floor } > ACKED_KEEP
                check(sp, acked, floor, exact = !overflowed, pairs = randomPairs(rnd, floor))
            }
            check(sp, acked, floor, exact = !overflowed, pairs = allPairs(floor))
        }
    }

    @Test fun bridgingRangeMergesEveryRangeItSpans() {
        val sp = PacketNumberSpace(SpaceId.Application)
        sp.recordAcked(10, 10)
        sp.recordAcked(20, 20)
        sp.recordAcked(30, 30)
        sp.recordAcked(40, 40)
        sp.recordAcked(5, 35) // spans 10, 20 and 30, stops short of 40
        assertTrue(sp.anyAckedBetween(36, 41), "40 is still acknowledged")
        assertEquals(false, sp.anyAckedBetween(35, 40), "36..39 were never acknowledged")
        assertTrue(sp.anyAckedBetween(4, 6))
        assertEquals(false, sp.anyAckedBetween(0, 5))
    }

    /**
     * Adjacent single packet numbers recorded in any order merge into one range: [ACKED_KEEP] slots are not used up by fragments, so
     * the unacknowledged gap 1..9 is never reported acknowledged (that would break a persistent congestion period that holds).
     */
    @Test fun negative_adjacentInsertsInAnyOrderDoNotExhaustTheRanges() {
        val xs = (10L..69L).toList()
        val orders =
            listOf(
                xs,
                xs.reversed(),
                xs.filter { it % 2 == 0L } + xs.filter { it % 2 == 1L },
                xs.filter { it % 2 == 1L } + xs.filter { it % 2 == 0L },
            ) +
                (1..5).map { xs.shuffled(kotlin.random.Random(it)) }
        for (order in orders) {
            val sp = PacketNumberSpace(SpaceId.Application)
            sp.recordAcked(0, 0)
            for (x in order) sp.recordAcked(x, x)
            assertEquals(false, sp.anyAckedBetween(0, 10), "1..9 never acknowledged; order $order")
            assertEquals(false, sp.anyAckedBetween(69, 80), "70..79 never acknowledged; order $order")
            for (x in listOf(0L) + xs) assertTrue(sp.anyAckedBetween(x - 1, x + 1), "$x acknowledged; order $order")
        }
    }

    /** A range above every kept one after a merge freed a slot is kept (the scan must not read the freed slot). */
    @Test fun rangeAboveAllAfterAMergeIsKept() {
        val sp = PacketNumberSpace(SpaceId.Application)
        sp.recordAcked(10, 10)
        sp.recordAcked(12, 12)
        sp.recordAcked(11, 11)
        sp.recordAcked(20, 20)
        assertTrue(sp.anyAckedBetween(19, 21))
        assertEquals(false, sp.anyAckedBetween(12, 20))
        val again = PacketNumberSpace(SpaceId.Application)
        for (x in listOf(10L, 12L, 11L, 13L)) again.recordAcked(x, x) // 13 extends the merged range; the freed slot still holds 12
        for (x in 10L..13L) assertTrue(again.anyAckedBetween(x - 1, x + 1), "$x acknowledged")
    }

    /**
     * Filling the gaps between [ACKED_KEEP] ranges merges them all, so later ranges find room and the oldest small ranges are not
     * forgotten (forgetting them makes the check report 1..2, never acknowledged, as acknowledged).
     */
    @Test fun gapFillingFreesSlotsForLaterRanges() {
        val sp = PacketNumberSpace(SpaceId.Application)
        sp.recordAcked(0, 0)
        sp.recordAcked(3, 3)
        for (x in 10L..68L step 2) sp.recordAcked(x, x) // 32 ranges: full
        for (x in 11L..67L step 2) sp.recordAcked(x, x) // fills every gap: 10..68 is one range
        sp.recordAcked(100, 100)
        sp.recordAcked(102, 102)
        assertEquals(false, sp.anyAckedBetween(0, 3), "1 and 2 were never acknowledged")
        assertEquals(false, sp.anyAckedBetween(3, 10))
    }

    /** Beyond [ACKED_KEEP] separate ranges every acknowledged number is still reported (conservatively), in any insertion order. */
    @Test fun negative_overflowNeverLosesAnAcknowledgedNumber() {
        val xs = (0L..40L).map { 4 * it }
        for (order in listOf(xs, xs.reversed(), xs.shuffled(kotlin.random.Random(7)))) {
            val sp = PacketNumberSpace(SpaceId.Application)
            for (x in order) sp.recordAcked(x, x)
            for (x in xs) assertTrue(sp.anyAckedBetween(x - 1, x + 1), "$x acknowledged; order $order")
            sp.recordAcked(41, 119) // bridges ranges 44..116 into one
            for (x in xs + (41L..119L)) assertTrue(sp.anyAckedBetween(x - 1, x + 1), "$x acknowledged after the bridge; order $order")
            assertEquals(false, sp.anyAckedBetween(156, 160), "157..159 never acknowledged")
        }
    }

    /** RFC 9002 section 7.6.2 across spaces: acknowledged send times strictly between the two lost packets' send times count. */
    @Test fun ackedSendTimesAreComparedStrictly() {
        val sp = PacketNumberSpace(SpaceId.Handshake)
        sp.recordAckedTime(TimeMark(100))
        assertTrue(sp.anyAckedSentBetween(TimeMark(99), TimeMark(101)))
        assertEquals(false, sp.anyAckedSentBetween(TimeMark(100), TimeMark(200)), "sent at the first lost packet's time")
        assertEquals(false, sp.anyAckedSentBetween(TimeMark(0), TimeMark(100)), "sent at the second lost packet's time")
    }

    /** Beyond the kept send times, a forgotten one still counts (conservatively) for an interval that starts before it. */
    @Test fun forgottenAckedSendTimesStillCount() {
        val sp = PacketNumberSpace(SpaceId.Handshake)
        for (t in 1L..(ACKED_TIMES_KEEP + 1L)) sp.recordAckedTime(TimeMark(t * 100))
        assertTrue(sp.anyAckedSentBetween(TimeMark(50), TimeMark(150)), "100 was forgotten but was acknowledged")
    }

    /** Pruning a full set of ranges keeps the rest, and a forgotten number at the prune point still counts. */
    @Test fun pruningAFullSetKeepsWhatLiesAbove() {
        val sp = PacketNumberSpace(SpaceId.Application)
        for (k in 0L..32L) sp.recordAcked(2 * k, 2 * k) // 33 ranges: 0 is forgotten into the unknown-below mark
        sp.pruneAckedBelow(0)
        assertTrue(sp.anyAckedBetween(-1, 1), "0 was acknowledged")
        sp.pruneAckedBelow(10)
        for (k in 5L..32L) assertTrue(sp.anyAckedBetween(2 * k - 1, 2 * k + 1), "${2 * k} acknowledged")
        assertEquals(false, sp.anyAckedBetween(10, 12))
    }

    private fun check(
        sp: PacketNumberSpace,
        acked: BooleanArray,
        floor: Int,
        exact: Boolean,
        pairs: List<Pair<Int, Int>>,
    ) {
        val ranges = rangesOf(acked).filter { it.last >= floor }
        for ((a, b) in pairs) {
            var expected = false
            for (x in a + 1 until b) if (x in 0 until UNIVERSE && acked[x]) expected = true
            val got = sp.anyAckedBetween(a.toLong(), b.toLong())
            if (expected) assertTrue(got, "($a, $b) holds an acknowledged packet; ranges $ranges, floor $floor")
            if (exact) assertEquals(expected, got, "($a, $b) within capacity; ranges $ranges")
        }
    }

    private fun allPairs(floor: Int): List<Pair<Int, Int>> =
        (floor - 1 until UNIVERSE).flatMap { a -> (a + 1..UNIVERSE).map { b -> a to b } }

    private fun randomPairs(
        rnd: kotlin.random.Random,
        floor: Int,
    ): List<Pair<Int, Int>> =
        List(200) {
            val a = rnd.nextInt(floor - 1, UNIVERSE)
            a to rnd.nextInt(a + 1, UNIVERSE + 1)
        }

    private fun rangesOf(acked: BooleanArray): List<IntRange> {
        val out = ArrayList<IntRange>()
        var i = 0
        while (i < acked.size) {
            if (!acked[i]) {
                i++
                continue
            }
            val s = i
            while (i < acked.size && acked[i]) i++
            out += s until i
        }
        return out
    }

    private companion object {
        const val UNIVERSE = 120
    }
}
