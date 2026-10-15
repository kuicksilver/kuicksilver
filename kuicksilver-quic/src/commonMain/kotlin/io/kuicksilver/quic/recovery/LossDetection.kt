// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.recovery

import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.wire.AckFrameView
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

internal enum class CongestionKind { Acked, Lost }

/** A reusable notification for the congestion controller. */
internal class CongestionEvent {
    var kind: CongestionKind = CongestionKind.Acked
    var bytes: Int = 0
    var sentTime: TimeMark = TimeMark(0)
    var now: TimeMark = TimeMark(0)
    var persistentCongestion: Boolean = false

    /** The path the packets travelled on: each path has its own congestion controller (RFC 9000 section 9.4). */
    var pathId: Int = 0

    /** The controller that counted the packets (null for packets sent before the connection had paths). */
    var cc: io.kuicksilver.quic.CongestionController? = null
}

/** A PTO expired: send [packets] ack-eliciting probes in [space] (RFC 9002 section 6.2.4). */
internal class PtoProbe(
    val space: SpaceId,
    val packets: Int,
)

internal interface LossListener {
    /**
     * One ACK frame that raised the largest acknowledged packet, for one path it newly acknowledged packets on: whether the frame
     * carried ECN counts, whether the counts moved consistently with the last ones of the space ([countsValid]: no decrease, no ECT(1),
     * growth of at least the newly acknowledged marked packets of all paths), how many newly acknowledged packets of [pathId] were sent
     * marked, whether the CE count grew (reported once, to the path of the largest newly acknowledged packet), that packet's send time.
     */
    fun onEcnAck(
        space: SpaceId,
        countsPresent: Boolean,
        countsValid: Boolean,
        newlyAckedMarked: Int,
        ceGrew: Boolean,
        now: TimeMark,
        largestSentTime: TimeMark,
        pathId: Int,
    ) {}

    /** A new RTT sample of the active path (for HyStart++ and the like). */
    fun onRttSample(
        now: TimeMark,
        latest: kotlin.time.Duration,
        min: kotlin.time.Duration,
    ) {}

    fun onAcked(
        space: SpaceId,
        p: SentPacket,
    )

    /**
     * A packet newly acknowledged by the ACK frame being processed, reported before that frame's loss detection runs (TCP's order:
     * delivery state first), for the delivery-rate sampler; [onAcked] follows after the losses.
     */
    fun onDelivered(
        p: SentPacket,
        now: TimeMark,
    ) {}

    /**
     * A packet declared lost earlier was acknowledged after all (RFC 9002 section 6.1: the loss was spurious): [bytes] counted by
     * [cc] on [pathId]. Reported once per packet, during the ACK frame that acknowledged it, before its loss detection.
     */
    fun onSpuriousLoss(
        space: SpaceId,
        pn: Long,
        bytes: Int,
        cc: io.kuicksilver.quic.CongestionController?,
        pathId: Int,
        now: TimeMark,
    ) {}

    /** A lost packet left the memory of spurious-loss detection unacknowledged (or its space was discarded): the loss stands. */
    fun onLossSettled(
        cc: io.kuicksilver.quic.CongestionController?,
        now: TimeMark,
    ) {}

    fun onLost(
        space: SpaceId,
        p: SentPacket,
    )

    fun onCongestion(event: CongestionEvent)

    /** An ACK frame is about to be processed: what the controllers have in flight now is their state "before the ACK". */
    fun onAckFrameStart() {}

    /** One ACK frame newly acknowledged packets and every one of them was reported: per-ACK controllers (BBR) update their model now. */
    fun onAckProcessed(now: TimeMark) {}

    /** Bytes removed from flight because their space was discarded. */
    fun onDiscarded(bytes: Int)
}

/** Loss detection and the PTO timer (RFC 9002 sections 5–6, appendix A), over the three packet number spaces. */
internal class LossDetection(
    rtt: RttEstimator,
    private val config: QuicConfig,
    private val role: TlsRole,
    private val listener: LossListener,
) {
    /** The active path's estimator; the core swaps it on migration. */
    var rtt: RttEstimator = rtt

    /** Only acknowledgements of packets sent on this path produce RTT samples. */
    var activePath: Int = 0
    private val spaces = Array(3) { PacketNumberSpace(SpaceId.entries[it], ackRanges = config.limits.ackRanges) }
    private val event = CongestionEvent()
    private val lost = ArrayList<SentPacket>()
    private val donePaths = IntArray(8)
    private val doneCcs = arrayOfNulls<io.kuicksilver.quic.CongestionController>(8)
    private val acked = ArrayList<SentPacket>()

    var handshakeConfirmed: Boolean = false

    /** When the connection took its first RTT sample (or the newest one after persistent congestion), [TimeMark.NEVER] before. */
    private var firstRttSampleTime: TimeMark = TimeMark.NEVER

    /** Client: the server has received a Handshake packet from us (our address is validated); server: always relevant through [handshakeConfirmed]. */
    var peerAddressValidated: Boolean = false
    var ptoCount: Int = 0
        private set
    var bytesInFlight: Long = 0
        private set
    var peerAckDelayExponent: Int = 3
    var peerMaxAckDelay: Duration = 25.milliseconds
    private var timerBase: TimeMark = TimeMark(0)

    fun space(id: SpaceId): PacketNumberSpace = spaces[id.ordinal]

    fun storedPackets(id: SpaceId): Int = space(id).sent.size

    /** Sent packets examined by [onAck] (the walk and the compaction), for the complexity tests. */
    internal var visitedForTest = 0

    fun onPacketSent(
        space: SpaceId,
        p: SentPacket,
        now: TimeMark,
    ) {
        val sp = this.space(space)
        if (p.pn > sp.largestSent) sp.largestSent = p.pn
        if (!p.ackEliciting && !p.inFlight) {
            sp.release(p)
            return
        }
        sp.sent.add(p)
        if (p.inFlight) bytesInFlight += p.size
        if (p.ackEliciting) {
            sp.lastAckElicitingTime = now
            sp.ackElicitingInFlight++
        }
        timerBase = now
    }

    fun onAck(
        space: SpaceId,
        ack: AckFrameView,
        now: TimeMark,
    ) {
        val sp = this.space(space)
        if (ack.largest >
            sp.largestSent
        ) {
            throw QuicWireException(
                TransportError.PROTOCOL_VIOLATION,
                0x02,
                "ACK for a packet never sent: largest ${ack.largest} > sent ${sp.largestSent} in $space " +
                    "($role, active path $activePath, ${sp.sent.size} in flight, next pn ${sp.nextPn}, " +
                    "largest acked ${sp.largestAcked}, ${ack.rangeCount} ranges, first [${ack.smallest(
                        0,
                    )}..${ack.largest(0)}])",
            )
        }
        if (sp.lastSkipped >=
            0
        ) {
            for (i in 0 until ack.rangeCount) {
                if (sp.lastSkipped in
                    ack.smallest(i)..ack.largest(i)
                ) {
                    throw QuicWireException(TransportError.PROTOCOL_VIOLATION, 0x02, "ACK for a skipped packet number")
                }
            }
        }
        listener.onAckFrameStart()
        val prevLargestAcked = sp.largestAcked
        if (ack.largest > sp.largestAcked) sp.largestAcked = ack.largest
        acked.clear()
        // RFC 9002 appendix A.7 without a pass over everything in flight (RFC 9000 section 21.6): ranges come in descending order,
        // each is found by binary search and walked downwards, so the first match is the largest newly acknowledged packet
        val sent = sp.sent
        for (r in 0 until ack.rangeCount) {
            val smallest = ack.smallest(r)
            if (sent.isEmpty() || ack.largest(r) < sent.pnAt(sent.start)) break // this and every later range lie below the oldest packet
            var i = sent.lowerBound(ack.largest(r) + 1) - 1
            val lo = sent.lowerBound(smallest)
            val before = acked.size
            while (i >= lo) {
                visitedForTest++
                val p = sent.at(i)
                if (p != null) {
                    acked += p
                    sent.removeAt(i)
                }
                i--
            }
            if (acked.size > before) sp.recordAcked(smallest, ack.largest(r))
        }
        for (k in acked.indices) listener.onDelivered(acked[k], now)
        settleLost(sp, now)
        if (sp.lostCount > 0) findSpurious(sp, space, ack, now)
        if (acked.isEmpty()) return
        visitedForTest += sent.trim()
        pruneAcked(sp)
        val largestNewlyAcked = acked[0] // the walk goes downwards: the first match is the largest
        if (largestNewlyAcked.pn == ack.largest && largestNewlyAcked.ackEliciting && largestNewlyAcked.pathId == activePath) {
            val maxMicros = Long.MAX_VALUE / 1000 shr peerAckDelayExponent
            val ackDelay =
                (
                    (
                        if (ack.ackDelay >
                            maxMicros
                        ) {
                            maxMicros
                        } else {
                            ack.ackDelay
                        }
                    ) shl peerAckDelayExponent
                ).let { micros ->
                    if (micros >
                        Long.MAX_VALUE / 1000
                    ) {
                        Duration.INFINITE
                    } else {
                        (micros * 1000).nanoseconds
                    }
                } // saturate: a peer-chosen value must not wrap
            rtt.onSample(now - largestNewlyAcked.timeSent, ackDelay, handshakeConfirmed, peerMaxAckDelay)
            if (firstRttSampleTime == TimeMark.NEVER) firstRttSampleTime = now
            listener.onRttSample(now, rtt.latest, rtt.min)
        }
        // RFC 9000 section 13.4.2.1: only an ACK that raises the largest acknowledged packet carries counts newer than the last ones
        if (ack.largest > prevLargestAcked) processEcn(sp, space, ack, now, largestNewlyAcked)
        detectLost(sp, now)
        for (k in acked.indices) {
            val p = acked[k]
            if (p.inFlight) bytesInFlight -= p.size
            if (p.ackEliciting) sp.ackElicitingInFlight--
            listener.onAcked(space, p)
            if (p.inFlight) {
                event.kind = CongestionKind.Acked
                event.bytes = p.size
                event.sentTime = p.timeSent
                event.now = now
                event.persistentCongestion =
                    false
                event.pathId = p.pathId
                event.cc = p.cc
                listener.onCongestion(event)
            }
            sp.release(p)
        }
        listener.onAckProcessed(now)
        if (peerCompletedAddressValidation()) ptoCount = 0
        timerBase = now
    }

    /** Lost packets of [sp] remembered longer than the persistent congestion period are settled: their loss stands. */
    private fun settleLost(
        sp: PacketNumberSpace,
        now: TimeMark,
    ) {
        if (sp.lostCount == 0) return
        val keepFrom = (now - persistentCongestionDuration()).nanos
        while (sp.lostCount > 0 && sp.lostAt[sp.lostHead] < keepFrom) dropOldestLost(sp, now)
    }

    private fun dropOldestLost(
        sp: PacketNumberSpace,
        now: TimeMark,
    ) {
        val h = sp.lostHead
        val cc = sp.lostCc[h]
        val live = sp.lostSize[h] > 0
        sp.lostCc[h] = null
        sp.lostHead = (h + 1) % LOST_KEEP
        sp.lostCount--
        if (live) listener.onLossSettled(cc, now)
    }

    private fun rememberLost(
        sp: PacketNumberSpace,
        p: SentPacket,
        now: TimeMark,
    ) {
        if (sp.lostCount == LOST_KEEP) dropOldestLost(sp, now)
        val i = (sp.lostHead + sp.lostCount) % LOST_KEEP
        sp.lostPn[i] = p.pn
        sp.lostSize[i] = p.size
        sp.lostAt[i] = now.nanos
        sp.lostPath[i] = p.pathId
        sp.lostCc[i] = p.cc
        sp.lostCount++
    }

    /**
     * Lost packets the ACK frame acknowledges: the ring ascends, the ranges descend, so one merge walk from the newest lost packet
     * costs at most the ring plus the ranges.
     */
    private fun findSpurious(
        sp: PacketNumberSpace,
        space: SpaceId,
        ack: AckFrameView,
        now: TimeMark,
    ) {
        var r = 0
        var k = sp.lostCount - 1
        while (k >= 0 && r < ack.rangeCount) {
            val i = (sp.lostHead + k) % LOST_KEEP
            val pn = sp.lostPn[i]
            if (pn > ack.largest(r)) {
                k--
                continue
            } // above this range, so above every later (smaller) one: not acknowledged
            if (pn < ack.smallest(r)) {
                r++
                continue
            } // below this range: try the next (smaller) one
            if (sp.lostSize[i] > 0) {
                val bytes = sp.lostSize[i]
                sp.lostSize[i] = 0
                listener.onSpuriousLoss(space, pn, bytes, sp.lostCc[i], sp.lostPath[i], now)
            }
            k--
        }
    }

    private var ecnPaths = IntArray(4)
    private var ecnMarkedPerPath = IntArray(4)

    /**
     * The ECN part of an ACK that raised the largest acknowledged packet (RFC 9000 section 13.4.2): the counts are compared with the
     * last ones of the space (kept in [PacketNumberSpace.peerEcn]) and must not decrease, must not show ECT(1) and must grow by at
     * least the newly acknowledged marked packets; every path with newly acknowledged packets then learns the verdict with its own
     * marked count, and CE growth is reported once, to the path of the largest newly acknowledged packet (as quic-go's ecn.go
     * validates per path from the connection-wide counts).
     */
    private fun processEcn(
        sp: PacketNumberSpace,
        space: SpaceId,
        ack: AckFrameView,
        now: TimeMark,
        largest: SentPacket,
    ) {
        var paths = 0
        var totalMarked = 0
        for (k in acked.indices) {
            val p = acked[k]
            var i = 0
            while (i < paths && ecnPaths[i] != p.pathId) i++
            if (i == paths) {
                if (paths == ecnPaths.size) {
                    ecnPaths = ecnPaths.copyOf(paths * 2)
                    ecnMarkedPerPath = ecnMarkedPerPath.copyOf(paths * 2)
                }
                ecnPaths[paths] = p.pathId
                ecnMarkedPerPath[paths] = 0
                paths++
            }
            if (p.ecnMarked) {
                ecnMarkedPerPath[i]++
                totalMarked++
            }
        }
        val counts = ack.ecn
        var valid = false
        var ceGrew = false
        if (counts != null) {
            val ect0 = counts[0] - (if (sp.peerEcnSeen) sp.peerEcn[0] else 0L)
            val ect1 = counts[1] - (if (sp.peerEcnSeen) sp.peerEcn[1] else 0L)
            val ce = counts[2] - (if (sp.peerEcnSeen) sp.peerEcn[2] else 0L)
            valid = ect0 >= 0 && ect1 == 0L && ce >= 0 && ect0 + ect1 + ce >= totalMarked
            ceGrew = ce > 0
            sp.peerEcn[0] = counts[0]
            sp.peerEcn[1] = counts[1]
            sp.peerEcn[2] = counts[2]
            sp.peerEcnSeen = true
        }
        for (i in 0 until paths) {
            val pid = ecnPaths[i]
            if (ecnMarkedPerPath[i] == 0 && pid != largest.pathId) continue // nothing of this path to validate
            listener.onEcnAck(
                space,
                counts != null,
                valid,
                ecnMarkedPerPath[i],
                ceGrew && pid == largest.pathId,
                now,
                largest.timeSent,
                pid,
            )
        }
    }

    private fun lossDelay(): Duration {
        val d =
            if (rtt.smoothed >
                rtt.latest
            ) {
                rtt.smoothed
            } else {
                rtt.latest
            }
        ; val delay = (d.inWholeNanoseconds * 9 / 8).nanoseconds
        return if (delay <
            1.milliseconds
        ) {
            1.milliseconds
        } else {
            delay
        }
    }

    private fun detectLost(
        sp: PacketNumberSpace,
        now: TimeMark,
    ) {
        sp.lossTime = TimeMark.NEVER
        val delay = lossDelay()
        val lostSendTime = now - delay
        lost.clear()
        // only packets below the largest acknowledged can be lost, and every one more than 3 below it is (packet threshold): the walk
        // costs the packets it declares lost plus at most 3 survivors and the tombstones between them
        val sent = sp.sent
        val end = sent.lowerBound(sp.largestAcked + 1)
        for (i in sent.start until end) {
            val p = sent.at(i) ?: continue
            if (p.timeSent <= lostSendTime || sp.largestAcked >= p.pn + 3) {
                lost += p
                sent.removeAt(i)
            } else {
                val t = p.timeSent + delay
                if (t < sp.lossTime) sp.lossTime = t
            }
        }
        if (lost.isEmpty()) return
        sent.trim()
        var lostBytes = 0
        settleLost(sp, now)
        for (k in lost.indices) {
            val p = lost[k]
            if (p.inFlight) {
                rememberLost(sp, p, now)
                lostBytes += p.size
                bytesInFlight -= p.size
            }
            if (p.ackEliciting) sp.ackElicitingInFlight--
            listener.onLost(sp.id, p)
        }
        val pcDuration = persistentCongestionDuration()
        var activePathPersistent = false
        // one loss event per path the lost packets travelled on: a migration must not charge the new path for the old one's losses (RFC 9000 section 9.4)
        if (lostBytes > 0) {
            var done = 0
            while (true) {
                // grouped by the controller that counted the packets (a rebinding moves a controller between paths), the path id rides along for ECN and diagnostics
                var pid = -1
                var pcc: io.kuicksilver.quic.CongestionController? = null
                var found = false
                for (k in lost.indices) {
                    val p = lost[k]
                    if (!p.inFlight) continue
                    var seen = false
                    for (d in 0 until done) {
                        if (donePaths[d] ==
                            p.pathId &&
                            doneCcs[d] === p.cc
                        ) {
                            seen = true
                        }
                    }
                    if (!seen) {
                        pid = p.pathId
                        pcc = p.cc
                        found = true
                        break
                    }
                }
                if (!found) break
                var bytes = 0
                var largest = TimeMark(Long.MIN_VALUE)
                for (k in lost.indices) {
                    val p = lost[k]
                    if (p.inFlight &&
                        p.pathId == pid &&
                        p.cc === pcc
                    ) {
                        bytes += p.size
                        if (p.timeSent > largest) largest = p.timeSent
                    }
                }
                val persistent = persistentCongestion(sp, pid, pcc, pcDuration)
                if (persistent && pid == activePath) activePathPersistent = true
                event.kind = CongestionKind.Lost
                event.bytes = bytes
                event.sentTime = largest
                event.now = now
                event.persistentCongestion =
                    persistent
                event.pathId = pid
                event.cc = pcc
                listener.onCongestion(event)
                if (done < donePaths.size) {
                    donePaths[done] = pid
                    doneCcs[done] = pcc
                    done++
                } else {
                    break
                }
            }
        }
        for (k in lost.indices) sp.release(lost[k])
        lost.clear()
        if (activePathPersistent) {
            // RFC 9002 section 5.2: min_rtt restarts from the newest sample, and (as ngtcp2) a new persistent congestion period
            // needs packets sent after it, so a lasting RTT increase is not declared persistent congestion again and again
            rtt.onPersistentCongestion()
            firstRttSampleTime = now
        }
    }

    /**
     * RFC 9002 section 7.6.2 for the lost packets of one path ([pid], counted by [pcc]): two ack-eliciting packets declared lost, no
     * packet sent between them acknowledged (packet numbers never stored, such as ACK-only packets, or skipped do not count), more
     * than [duration] apart, and both sent after the first RTT sample ("The persistent congestion period SHOULD NOT start until
     * there is at least one RTT sample"; ngtcp2 filters by first_rtt_sample_ts the same way).
     */
    private fun persistentCongestion(
        sp: PacketNumberSpace,
        pid: Int,
        pcc: io.kuicksilver.quic.CongestionController?,
        duration: Duration,
    ): Boolean {
        if (!rtt.hasSample || firstRttSampleTime == TimeMark.NEVER) return false
        var runStart = TimeMark.NEVER
        var prevPn = -1L
        for (k in lost.indices) {
            val p = lost[k]
            if (!p.ackEliciting || !p.inFlight || p.pathId != pid || p.cc !== pcc) continue
            if (p.timeSent < firstRttSampleTime) continue
            if (runStart == TimeMark.NEVER || sp.anyAckedBetween(prevPn, p.pn)) runStart = p.timeSent
            prevPn = p.pn
            if (p.timeSent - runStart > duration) return true
        }
        return false
    }

    /** The acknowledged ranges below the oldest packet still held can never separate two lost packets. */
    private fun pruneAcked(sp: PacketNumberSpace) {
        val sent = sp.sent
        if (sent.isEmpty()) sp.clearAcked() else sp.pruneAckedBelow(sent.pnAt(sent.start))
    }

    private fun peerCompletedAddressValidation(): Boolean = role == TlsRole.Server || peerAddressValidated || handshakeConfirmed

    private fun pto(space: SpaceId): Duration {
        val v4 = rtt.rttVar * 4
        var d = rtt.smoothed + (if (v4 > 1.milliseconds) v4 else 1.milliseconds)
        if (space == SpaceId.Application && handshakeConfirmed) d += peerMaxAckDelay
        return d * (1 shl ptoCount)
    }

    /** The persistent congestion period (RFC 9002 section 7.6.1): (sRTT + max(4 rttvar, granularity) + max_ack_delay) × 3. */
    fun persistentCongestionDuration(): Duration {
        val v4 =
            rtt.rttVar * 4
        return (rtt.smoothed + (if (v4 > 1.milliseconds) v4 else 1.milliseconds) + peerMaxAckDelay) * 3
    }

    /** The space the last [earliestLossTime] / [ptoTimeAndSpace] result refers to (fields instead of a Pair: no allocation per timer query). */
    private var timerSpace = SpaceId.Initial

    private fun earliestLossTime(): TimeMark {
        var best = TimeMark.NEVER
        for (i in spaces.indices) {
            val sp = spaces[i]
            if (sp.lossTime <
                best
            ) {
                best = sp.lossTime
                timerSpace = sp.id
            }
        }
        return best
    }

    /** Server: true while the anti-amplification limit leaves nothing to send; no PTO is armed then (RFC 9002 section 6.2.2.1). */
    var amplificationBlocked: (() -> Boolean)? = null

    private fun ptoTimeAndSpace(): TimeMark {
        if (amplificationBlocked?.invoke() == true) return TimeMark.NEVER
        var anyElicitingInFlight = false
        for (i in spaces.indices) if (spaces[i].ackElicitingInFlight > 0) anyElicitingInFlight = true
        if (!anyElicitingInFlight) { // padding-only packets count as in flight but elicit nothing
            if (peerCompletedAddressValidation()) return TimeMark.NEVER
            // client before the server validated its address: arm a PTO anyway so a lost flight is repaired (anti-deadlock, section 6.2.2.1)
            val space = if (handshakeKeysAvailable) SpaceId.Handshake else SpaceId.Initial
            timerSpace = space
            return timerBase + pto(space)
        }
        var best = TimeMark.NEVER
        for (i in spaces.indices) {
            val sp = spaces[i]
            if (sp.ackElicitingInFlight <= 0) continue
            // RFC 9002 section 6.2.1: no 1-RTT PTO before the handshake is confirmed
            if (sp.id == SpaceId.Application && !handshakeConfirmed) continue
            if (sp.lastAckElicitingTime == TimeMark.NEVER) continue
            val t = sp.lastAckElicitingTime + pto(sp.id)
            if (t < best) {
                best = t
                timerSpace = sp.id
            }
        }
        return best
    }

    /**
     * The [n] oldest unacknowledged packets of [space] whose frames a PTO probe can send again ([SentFrames.probeContent]) and that
     * no earlier probe took; each is marked [SentPacket.probed]. A probe's own copy is a newer packet that a later PTO takes, so
     * successive probes cycle through everything outstanding instead of repeating the oldest packets: when those hold only a PING
     * or NEW_CONNECTION_ID frames and every acknowledgement is lost, the data behind them would otherwise never be resent.
     */
    fun takeForProbe(
        space: SpaceId,
        n: Int,
        out: MutableList<SentPacket>,
    ) {
        val sp = this.space(space)
        for (p in sp.sent) {
            if (out.size >=
                n
            ) {
                break
            }
            if (p.ackEliciting && !p.probed && p.frames.probeContent()) {
                p.probed = true
                out += p
            }
        }
    }

    /** Set by the core once Handshake keys exist (anti-deadlock probes then go to the Handshake space). */
    var handshakeKeysAvailable: Boolean = false

    /** The next time [onTimeout] must run, or [TimeMark.NEVER] when no timer is armed. */
    fun timeout(): TimeMark {
        val loss = earliestLossTime()
        return if (loss != TimeMark.NEVER) loss else ptoTimeAndSpace()
    }

    /** Runs the expired timer: lost packets are reported through the listener; a PTO returns the probe to send. */
    fun onTimeout(now: TimeMark): PtoProbe? {
        val loss = earliestLossTime()
        if (loss <= now) {
            detectLost(space(timerSpace), now)
            return null
        }
        if (ptoTimeAndSpace() == TimeMark.NEVER) return null
        ptoCount++
        timerBase = now
        return PtoProbe(timerSpace, if (bytesInFlight > 0) 2 else 1)
    }

    /** Drops the keys' space (RFC 9002 section 6.4): its packets leave the in-flight accounting and timers. */

    /**
     * Removes the 0-RTT packets of the Application space (rejected 0-RTT, a Retry or a Version Negotiation restart): out of
     * flight without a congestion signal (RFC 9002 section 6.4), [each] sees them first to queue their frames again.
     */
    fun discardZeroRtt(each: (SentPacket) -> Unit) {
        val sp = space(SpaceId.Application)
        var removed = 0
        for (i in sp.sent.start until sp.sent.end) {
            val p = sp.sent.at(i) ?: continue
            if (!p.zeroRtt) continue
            each(p)
            if (p.inFlight) {
                bytesInFlight -= p.size
                removed += p.size
            }
            if (p.ackEliciting) sp.ackElicitingInFlight--
            sp.sent.removeAt(i)
            sp.release(p)
        }
        sp.sent.trim()
        if (removed > 0) listener.onDiscarded(removed)
    }

    fun discard(
        space: SpaceId,
        now: TimeMark = TimeMark(0),
    ) {
        val sp = this.space(space)
        while (sp.lostCount > 0) dropOldestLost(sp, now)
        var removed = 0
        for (p in sp.sent) {
            if (p.inFlight) {
                bytesInFlight -= p.size
                removed += p.size
            }
            sp.release(p)
        }
        if (removed > 0) listener.onDiscarded(removed)
        sp.sent.clear()
        sp.clearAcked()
        sp.lossTime = TimeMark.NEVER
        sp.lastAckElicitingTime = TimeMark.NEVER
        sp.ackElicitingInFlight = 0
        ptoCount = 0
    }
}
