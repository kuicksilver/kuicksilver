// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.time.Duration

/**
 * Congestion control of one path (RFC 9002 section 7). The core calls these from its single-threaded loop; a controller
 * never blocks and never allocates on the hot path. [Cubic] with HyStart++ is the default; [NewReno] and the experimental [Bbr] are choices.
 */
@ExperimentalKuicksilverApi
@SubclassOptInRequired(ExperimentalKuicksilverApi::class)
public interface CongestionController {
    /** A packet of [bytes] that counts in flight left at [now] (RFC 9002 section 7). */
    public fun onPacketSent(
        now: TimeMark,
        bytes: Int,
    )

    /**
     * [bytes] sent at [sentTime] were acknowledged at [now]; [appLimited] means the sender had nothing more to send then, so the window
     * must not grow on it (RFC 9002 section 7.8).
     */
    public fun onAck(
        now: TimeMark,
        sentTime: TimeMark,
        bytes: Int,
        smoothedRtt: Duration,
        appLimited: Boolean,
    )

    /**
     * [lostBytes] were declared lost (RFC 9002 section 6.1); one reduction per recovery period, judged by [largestLostSentTime];
     * [persistentCongestion] collapses the window to its minimum (section 7.6).
     */
    public fun onLoss(
        now: TimeMark,
        lostBytes: Int,
        largestLostSentTime: TimeMark,
        persistentCongestion: Boolean,
    )

    /**
     * The peer reported new ECN-CE marks for packets up to one sent at [sentTime]: a congestion event, once per recovery period (RFC 9002
     * section 7.1).
     */
    public fun onEcnCe(
        now: TimeMark,
        sentTime: TimeMark,
    )

    /** An RTT sample of the active path (RFC 9002 section 5); HyStart++ listens, others may ignore it. */
    public fun onRttSample(
        now: TimeMark,
        latest: Duration,
        min: Duration,
    ) {}

    /** The path's datagram size changed to [maxDatagramSize] bytes (PMTUD, RFC 9000 section 14); windows counted in datagrams follow it. */
    public fun onMtuUpdate(maxDatagramSize: Int)

    /** Packets of a discarded packet number space leave the in-flight count without a congestion event (RFC 9002 section 6.4). */
    public fun onDiscarded(bytes: Int)

    /** Congestion window in bytes. */
    public val cwnd: Long

    /** Bytes sent and neither acknowledged, lost nor discarded yet, as this controller counts them. */
    public val bytesInFlight: Long

    /** Pacing rate in bytes per second for the current window. */
    public fun pacingRate(smoothedRtt: Duration): Long

    /** Largest burst the sender hands to the socket at once: at most 65 536 bytes, or two datagrams when those are larger. */
    public val sendQuantum: Int
}
