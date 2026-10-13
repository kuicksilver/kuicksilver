// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.TimeMark
import kotlin.random.Random

/** Sending and receiving state of one packet number space (shared by every path of the connection). */
internal class PacketNumberSpace(
    val id: SpaceId,
    ackRanges: Int = 64,
) {
    var nextPn: Long = 0
    var largestAcked: Long = -1

    /** Largest packet number handed to loss detection; an ACK above it is a PROTOCOL_VIOLATION. */
    var largestSent: Long = -1
    val ack: AckTracker = AckTracker(ackRanges, immediate = id != SpaceId.Application)

    /** The most recently skipped packet number (Application space only, RFC 9000 section 21.4), -1 when none. */
    var lastSkipped: Long = -1
        private set
    private var nextSkip: Long = -1

    internal val sent = SentPackets()

    /** The peer's last reported ECN counts for this space (ECT(0), ECT(1), CE), taken from ACKs that raised the largest acknowledged packet (RFC 9000 section 13.4.2.1). */
    internal val peerEcn = LongArray(3)
    internal var peerEcnSeen = false
    internal var lossTime: TimeMark = TimeMark.NEVER
    internal var lastAckElicitingTime: TimeMark = TimeMark.NEVER
    internal var ackElicitingInFlight = 0
    private val pool = ArrayList<SentPacket>()

    /**
     * In-flight packets declared lost, remembered for a while so an acknowledgement that arrives after all shows the loss was
     * spurious (RFC 9002 section 6.1: reordering or a delay spike, not congestion). A ring of [LOST_KEEP] in ascending packet
     * number order (later losses are always of later packets); a size of 0 marks one acknowledged since.
     */
    internal val lostPn = LongArray(LOST_KEEP)
    internal val lostSize = IntArray(LOST_KEEP)
    internal val lostAt = LongArray(LOST_KEEP)
    internal val lostPath = IntArray(LOST_KEEP)
    internal val lostCc = arrayOfNulls<io.kuicksilver.quic.CongestionController>(LOST_KEEP)
    internal var lostHead = 0
    internal var lostCount = 0

    /**
     * Packet number ranges the peer acknowledged that may lie between two packets still to be declared lost (RFC 9002 section 7.6.2:
     * persistent congestion needs that "none of the packets sent between the send times of these two packets are acknowledged").
     * Ascending, disjoint; ranges below the oldest outstanding packet are pruned. At most [ACKED_KEEP]: when one more is needed
     * the lowest is forgotten and [ackedUnknownBelow] covers it, which only ever makes the check more conservative.
     */
    private val ackedLo = LongArray(ACKED_KEEP)
    private val ackedHi = LongArray(ACKED_KEEP)
    private var ackedCount = 0
    private var ackedUnknownBelow = -1L

    /** The peer acknowledged every packet number in [lo]..[hi]. */
    internal fun recordAcked(
        lo: Long,
        hi: Long,
    ) {
        var i = 0
        while (i < ackedCount && ackedHi[i] < lo - 1) i++
        if (i < ackedCount && ackedLo[i] <= hi + 1) {
            if (lo < ackedLo[i]) ackedLo[i] = lo
            if (hi > ackedHi[i]) ackedHi[i] = hi
            while (i + 1 < ackedCount && ackedLo[i + 1] <= ackedHi[i] + 1) {
                if (ackedHi[i + 1] > ackedHi[i]) ackedHi[i] = ackedHi[i + 1]
                removeAcked(i + 1)
            }
            return
        }
        if (ackedCount == ACKED_KEEP) {
            if (hi <= ackedHi[0]) {
                if (hi > ackedUnknownBelow) ackedUnknownBelow = hi
                return
            }
            if (ackedHi[0] > ackedUnknownBelow) ackedUnknownBelow = ackedHi[0]
            removeAcked(0)
            if (i > 0) i--
        }
        for (k in ackedCount downTo i + 1) {
            ackedLo[k] = ackedLo[k - 1]
            ackedHi[k] = ackedHi[k - 1]
        }
        ackedLo[i] = lo
        ackedHi[i] = hi
        ackedCount++
    }

    private fun removeAcked(i: Int) {
        for (k in i until ackedCount - 1) {
            ackedLo[k] = ackedLo[k + 1]
            ackedHi[k] = ackedHi[k + 1]
        }
        ackedCount--
    }

    /** Whether a packet number strictly between [a] and [b] may have been acknowledged. */
    internal fun anyAckedBetween(
        a: Long,
        b: Long,
    ): Boolean {
        if (b - a < 2) return false
        if (a + 1 <= ackedUnknownBelow) return true
        for (i in 0 until ackedCount) {
            if (ackedLo[i] >= b) return false
            if (ackedHi[i] > a) return true
        }
        return false
    }

    /** Forgets the acknowledged ranges below [pn], the oldest packet loss detection still holds: no lost pair can span them. */
    internal fun pruneAckedBelow(pn: Long) {
        var drop = 0
        while (drop < ackedCount && ackedHi[drop] < pn) drop++
        if (drop > 0) {
            for (k in 0 until ackedCount - drop) {
                ackedLo[k] = ackedLo[k + drop]
                ackedHi[k] = ackedHi[k + drop]
            }
            ackedCount -= drop
        }
        if (ackedUnknownBelow < pn) ackedUnknownBelow = -1L
    }

    internal fun clearAcked() {
        ackedCount = 0
        ackedUnknownBelow = -1L
    }

    /** The next packet number; now and then one is skipped so an optimistic ACK is detectable (RFC 9000 section 21.4; one in every [128, 1024) packets). */
    fun takePn(random: Random): Long {
        if (id == SpaceId.Application) {
            if (nextSkip < 0) nextSkip = nextPn + random.nextInt(128, 1024)
            if (nextPn == nextSkip) {
                lastSkipped = nextPn
                nextPn++
                nextSkip = lastSkipped + random.nextInt(128, 1024)
            }
        }
        return nextPn++
    }

    fun newSentPacket(): SentPacket = pool.removeLastOrNull() ?: SentPacket()

    internal fun release(p: SentPacket) {
        p.reset()
        pool += p
    }
}

/** Lost packets each space remembers for spurious-loss detection; more within the retention time settle the oldest early. */
internal const val LOST_KEEP = 64

/** Acknowledged ranges each space remembers for the persistent congestion check. */
internal const val ACKED_KEEP = 32
