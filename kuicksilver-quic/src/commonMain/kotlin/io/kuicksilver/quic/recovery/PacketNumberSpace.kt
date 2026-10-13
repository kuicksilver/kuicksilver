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
