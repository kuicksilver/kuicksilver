// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.wire.FrameEncoder
import io.kuicksilver.quic.wire.WireWriter
import kotlin.time.Duration

/**
 * Received packet numbers of one space and the ACK policy of RFC 9000 section 13.2: an ACK after every second
 * ack-eliciting packet or `max_ack_delay`, immediately for Initial/Handshake and on reordering. Ranges are kept
 * as (smallest, largest) pairs in descending order, capped at [maxRanges] by dropping the oldest.
 */
internal class AckTracker(
    private val maxRanges: Int,
    private val immediate: Boolean = false,
) {
    private var ranges = LongArray(2 * maxRanges)
    private var count = 0
    private var largest = -1L
    private var largestTime = TimeMark(0)
    private var pending = 0 // ack-eliciting packets since the last ACK we sent
    private var firstPendingTime = TimeMark(0)
    private var required = false

    /** Packets at or below this are no longer reported (the peer acknowledged our ACK for them). */
    private var floor = -1L

    /** Highest packet number of a range dropped for lack of room: anything at or below it is reported as seen. */
    private var evictedBelow = -1L

    /**
     * Packets processed in part and then dropped unacknowledged (a STREAM frame refused for lack of reassembly room after the frames
     * ahead of it were applied): seen, so a copy is a duplicate (RFC 9000 section 12.3), yet never acknowledged, as not all of
     * their frames were processed (section 13.1). At most [REFUSED_KEPT]; the lowest goes first.
     */
    private val refused = LongArray(REFUSED_KEPT)
    private var refusedCount = 0

    /** Highest refused packet number dropped from [refused] for lack of room: anything at or below it is treated as seen. */
    private var refusedBelow = -1L

    /** ECT(0), ECT(1), CE counts of processed packets (RFC 9000 section 13.4.1); null until a mark was seen, then ACK frames become ACK_ECN. */
    var ecnCounts: LongArray? = null
        private set

    fun onEcn(ecn: io.kuicksilver.quic.Ecn) {
        if (ecn ==
            io.kuicksilver.quic.Ecn.NotEct
        ) {
            return
        }
        val c =
            ecnCounts ?: LongArray(3).also { ecnCounts = it }
        when (ecn) {
            io.kuicksilver.quic.Ecn.Ect0 -> {
                c[0]++
            }

            io.kuicksilver.quic.Ecn.Ect1 -> {
                c[1]++
            }

            io.kuicksilver.quic.Ecn.Ce -> {
                c[2]++
            }
        }
    }

    val ackRequired: Boolean get() = required
    val largestReceived: Long get() = largest
    val rangeCount: Int get() = count

    fun isDuplicate(pn: Long): Boolean {
        if (pn <= floor || pn <= evictedBelow || pn <= refusedBelow) return true
        for (k in 0 until refusedCount) if (refused[k] == pn) return true
        for (i in 0 until count) {
            if (pn > ranges[2 * i + 1]) return false
            if (pn >= ranges[2 * i]) return true
        }
        return false // below every tracked range but never evicted: a reordered packet we have not seen (RFC 9000 section 13.2.3)
    }

    /** Packet [pn] was processed in part and dropped unacknowledged: a copy of it is a duplicate from now on, and it is never acknowledged. */
    fun onPacketRefused(pn: Long) {
        if (isDuplicate(pn)) return // seen already (below a floor, or kept): it must not push a kept refusal out
        if (refusedCount == REFUSED_KEPT) {
            var lowest = 0
            for (k in 1 until refusedCount) if (refused[k] < refused[lowest]) lowest = k
            if (refused[lowest] > refusedBelow) refusedBelow = refused[lowest]
            refused[lowest] = refused[--refusedCount]
        }
        refused[refusedCount++] = pn
    }

    /** [ce]: the packet arrived marked Congestion Experienced (RFC 9000 section 13.2.1: acknowledged immediately). */
    fun onPacketReceived(
        pn: Long,
        ackEliciting: Boolean,
        now: TimeMark,
        ce: Boolean = false,
    ) {
        if (pn <= floor || pn <= evictedBelow) return
        val reordered = largest >= 0 && (pn < largest || pn > largest + 1)
        insert(pn)
        if (pn > largest) {
            largest = pn
            largestTime = now
        }
        if (ackEliciting) {
            pending++
            if (pending == 1) firstPendingTime = now
            if (immediate || pending >= 2 || reordered || ce) required = true
        }
    }

    private fun insert(pn: Long) {
        var i = 0
        while (i < count && pn < ranges[2 * i] - 1) i++
        if (i < count && pn >= ranges[2 * i] - 1 && pn <= ranges[2 * i + 1] + 1) {
            if (pn == ranges[2 * i] - 1) ranges[2 * i] = pn
            if (pn == ranges[2 * i + 1] + 1) ranges[2 * i + 1] = pn
            if (i > 0 && ranges[2 * (i - 1)] == ranges[2 * i + 1] + 1) {
                ranges[2 * i + 1] = ranges[2 * (i - 1) + 1]
                removeAt(i - 1)
                i--
            }
            if (i + 1 < count && ranges[2 * (i + 1) + 1] == ranges[2 * i] - 1) {
                ranges[2 * i] = ranges[2 * (i + 1)]
                removeAt(i + 1)
            }
            return
        }
        if (count ==
            maxRanges
        ) {
            val dropped = ranges[2 * (count - 1) + 1]
            if (dropped >
                evictedBelow
            ) {
                evictedBelow = dropped
            }
            count--
            if (i > count) i = count
        } // drop the lowest range
        for (j in count downTo i + 1) {
            ranges[2 * j] = ranges[2 * (j - 1)]
            ranges[2 * j + 1] = ranges[2 * (j - 1) + 1]
        }
        ranges[2 * i] = pn
        ranges[2 * i + 1] = pn
        count++
    }

    private fun removeAt(i: Int) {
        for (j in i until count - 1) {
            ranges[2 * j] = ranges[2 * (j + 1)]
            ranges[2 * j + 1] =
                ranges[2 * (j + 1) + 1]
        }
        count--
    }

    /** When an ACK has to leave: now if required, else `first pending + maxAckDelay`; null with nothing to acknowledge. */
    fun ackDeadline(maxAckDelay: Duration): TimeMark =
        if (pending ==
            0
        ) {
            TimeMark.NEVER
        } else if (required) {
            firstPendingTime
        } else {
            firstPendingTime + maxAckDelay
        }

    /** True when an ACK frame can be written (anything received and not yet reported). */
    val hasRanges: Boolean get() = count > 0

    fun writeAck(
        w: WireWriter,
        now: TimeMark,
        ackDelayExponent: Int,
    ) {
        val delay = (now - largestTime).inWholeMicroseconds ushr ackDelayExponent
        FrameEncoder.ack(w, ranges, count, delay, ecnCounts)
        pending = 0
        required = false
    }

    fun ackOverhead(
        now: TimeMark,
        ackDelayExponent: Int,
    ): Int =
        if (count ==
            0
        ) {
            0
        } else {
            FrameEncoder.ackOverhead(ranges, count, (now - largestTime).inWholeMicroseconds ushr ackDelayExponent, ecnCounts)
        }

    /**
     * The peer acknowledged one of our packets that carried an ACK frame whose Largest Acknowledged was [largestInFrame]
     * (kept in the packet's [SentFrames.ackLargest]): ranges at or below it need no further reporting (RFC 9000 section 13.2.4).
     */
    fun onAckFrameAcknowledged(largestInFrame: Long) {
        if (largestInFrame <= floor) return
        floor = largestInFrame
        var j = 0
        while (j <
            count
        ) {
            if (ranges[2 * j + 1] <= floor) {
                removeAt(j)
            } else {
                if (ranges[2 * j] <= floor) ranges[2 * j] = floor + 1
                j++
            }
        }
    }

    private companion object {
        /** Refused packets remembered one by one; beyond that the oldest becomes a floor (refusals come only under reassembly pressure). */
        const val REFUSED_KEPT = 16
    }
}
