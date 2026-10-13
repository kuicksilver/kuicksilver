// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.TimeMark

/**
 * Delivery-rate sampling (draft-ietf-ccwg-bbr section 4.1, formerly draft-cheng-iccrg-delivery-rate-estimation) for one
 * controller: each packet carries a snapshot of the connection's delivery state from when it left ([SentPacket.rsId] and
 * friends), and an ACK turns the snapshot of the most recently sent packet it acknowledges into one rate sample:
 * data delivered since that packet left over the longer of its send and ACK intervals. Application-limited phases mark
 * the packets sent in them so a sample that only shows the application's pace never lowers the model. All state is in
 * fields, one sample per ACK: [begin], [onAcked] for each newly acknowledged packet, [generate].
 */
internal class DeliveryRateSampler {
    /** C.delivered: bytes acknowledged over the lifetime of the controller, and when that last grew. */
    var delivered: Long = 0
        private set
    var deliveredTime: TimeMark = TimeMark(0)
        private set

    /** C.first_send_time: send time of the latest packet acknowledged (or of the first one after an idle period). */
    var firstSentTime: TimeMark = TimeMark(0)
        private set

    /** C.app_limited: the delivered count that ends the current application-limited phase, 0 when not application-limited. */
    var appLimited: Long = 0
        private set

    /** C.lost: bytes declared lost over the lifetime of the controller. */
    var lost: Long = 0
        private set
    private var nextId: Long = 0

    // the rate sample of the ACK being processed (RS); valid after [generate] returned true
    var hasData: Boolean = false
        private set

    /** P.delivered of the most recently sent packet the ACK acknowledged. */
    var priorDelivered: Long = 0
        private set
    private var sendElapsed: Long = 0
    private var ackElapsed: Long = 0
    private var lastAckedId: Long = -1
    private var lastAckedLost: Long = 0

    /** The sample's application-limited flag (that packet's), its C.inflight at send and the bytes lost since it left. */
    var sampleAppLimited: Boolean = false
        private set
    var sampleTxInFlight: Long = 0
        private set
    val sampleLost: Long get() = lost - lastAckedLost

    /** RTT of the most recently sent packet acknowledged, in nanoseconds; -1 without one. */
    var sampleRttNanos: Long = -1
        private set

    /** Bytes newly acknowledged and newly lost since [begin]. */
    var newlyAcked: Long = 0
        private set
    var newlyLost: Long = 0
        private set

    /** RS.delivered: bytes delivered over the sampling interval; RS.interval in nanoseconds. */
    var sampleDelivered: Long = 0
        private set
    var intervalNanos: Long = 0
        private set

    /** RS.delivery_rate in bytes per second, 0 when the sample is not reliable. */
    var deliveryRate: Long = 0
        private set

    /** OnPacketSent (section 4.1.2.2): [inflight] already counts [p]. */
    fun onSent(
        p: SentPacket,
        now: TimeMark,
        inflight: Long,
    ) {
        if (inflight == p.size.toLong()) {
            firstSentTime = now
            deliveredTime = now
        } // nothing else in flight: the interval starts now
        p.rsId = nextId++
        p.rsFirstSentTime = firstSentTime
        p.rsDeliveredTime = deliveredTime
        p.rsDelivered = delivered
        p.rsAppLimited = appLimited != 0L
        p.rsTxInFlight = inflight
        p.rsLost = lost
    }

    /** InitRateSample: a new ACK. */
    fun begin() {
        hasData = false
        newlyAcked = 0
        newlyLost = 0
        sampleRttNanos = -1
        deliveryRate = 0
        intervalNanos = 0
        sampleDelivered = 0
    }

    /** UpdateRateSample (section 4.1.2.3) for one newly acknowledged packet that [onSent] stamped. */
    fun onAcked(
        p: SentPacket,
        now: TimeMark,
    ) {
        if (p.rsId < 0) return
        delivered += p.size
        newlyAcked += p.size
        deliveredTime = now
        if (!hasData || p.rsId > lastAckedId) {
            hasData = true
            priorDelivered = p.rsDelivered
            sampleAppLimited = p.rsAppLimited
            sampleTxInFlight = p.rsTxInFlight
            lastAckedLost = p.rsLost
            sendElapsed = (p.timeSent - p.rsFirstSentTime).inWholeNanoseconds
            ackElapsed = (now - p.rsDeliveredTime).inWholeNanoseconds
            sampleRttNanos = (now - p.timeSent).inWholeNanoseconds
            lastAckedId = p.rsId
            firstSentTime = p.timeSent
        } // the most recently sent packet carries the freshest snapshot
    }

    /** A stamped packet was declared lost. */
    fun onLost(p: SentPacket) {
        if (p.rsId < 0) return
        lost += p.size
        newlyLost += p.size
    }

    /**
     * GenerateRateSample: false when the ACK acknowledged nothing stamped. A sample whose interval is shorter than [minRttNanos]
     * (ACK compression) keeps [deliveryRate] 0 (section 4.1.2.3).
     */
    fun generate(minRttNanos: Long): Boolean {
        if (appLimited != 0L && delivered > appLimited) appLimited = 0 // the bubble was acknowledged
        if (!hasData) return false
        intervalNanos = maxOf(sendElapsed, ackElapsed)
        sampleDelivered = delivered - priorDelivered
        if (intervalNanos < minRttNanos || intervalNanos <= 0) return true
        deliveryRate = (sampleDelivered.toDouble() * 1e9 / intervalNanos).toLong()
        return true
    }

    /** MarkConnectionAppLimited (section 4.1.2.4): the packets in flight and those sent until they are acknowledged are application-limited. */
    fun markAppLimited(inflight: Long) {
        appLimited = maxOf(delivered + inflight, 1L)
    }
}
