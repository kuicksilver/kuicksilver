// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.TimeMark
import kotlin.random.Random

/** Sending and receiving state of one packet number space on one path. */
internal class PacketNumberSpace(
    val id: SpaceId,
    val path: PathId = PathId.Initial,
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
