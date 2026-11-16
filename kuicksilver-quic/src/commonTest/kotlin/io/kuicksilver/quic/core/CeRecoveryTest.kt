// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.Cubic
import io.kuicksilver.quic.NewReno
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.endpoint.EndpointPair
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.recovery.SpaceId
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * RFC 9002 section 7.3.2 and appendix B.6-B.8: losses and ECN-CE reports share one recovery period per controller
 * (congestion_recovery_start_time), judged by InCongestionRecovery(sent_time) of the packet that signalled the event; persistent
 * congestion ends it. The core forwards every valid CE report to the path's controller, which alone decides.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class CeRecoveryTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun ce(
        c: ConnectionCore,
        now: TimeMark,
        sent: TimeMark,
        path: PathId = c.path.id,
    ) = ConnectionLossListener(c).onEcnAck(SpaceId.Application, true, true, 1, true, now, sent, path.value)

    private fun controllers(): List<Pair<String, () -> CongestionController>> = listOf("NewReno" to { NewReno() }, "Cubic" to { Cubic() })

    /**
     * RFC 9002 section 7.3.2: "A NewReno sender enters a recovery period when it detects the loss of a packet or when the ECN-CE
     * count reported by its peer increases." A loss starts recovery at t1; a CE report for a packet sent after t1 is outside it
     * (appendix B.6: InCongestionRecovery is false), a new congestion event, even after an earlier CE report the controller ignored.
     */
    @Test fun negative_ceAfterLossStartedRecoveryIsANewCongestionEvent() {
        for ((name, factory) in controllers()) {
            val p = EndpointPair()
            val c = p.connect(quicConfig { congestionController = factory })
            p.use { _ ->
                assertTrue(p.confirmed(c))
                val cc = c.path.cc
                val t1 = p.now
                cc.onLoss(t1, 0, t1 - 5.milliseconds, false)
                val afterLoss = cc.cwnd
                val events = c.stats.ecnCeEvents
                ce(c, t1 + 20.milliseconds, t1 - 2.milliseconds)
                assertEquals(afterLoss, cc.cwnd, "$name: a CE for a packet sent before the recovery began changes nothing")
                assertEquals(events, c.stats.ecnCeEvents, "$name: and is no congestion event")
                ce(c, t1 + 40.milliseconds, t1 + 10.milliseconds)
                assertTrue(cc.cwnd < afterLoss, "$name: a CE for a packet sent after the recovery began reduces: ${cc.cwnd} vs $afterLoss")
                assertEquals(events + 1, c.stats.ecnCeEvents, "$name: one congestion event")
            }
        }
    }

    /**
     * Appendix B.8: persistent congestion sets congestion_recovery_start_time to 0, so the next CE report is a new congestion event
     * whatever its packet's send time, also one sent before an earlier CE-started recovery period.
     */
    @Test fun negative_ceAfterPersistentCongestionIsANewCongestionEvent() {
        for ((name, factory) in controllers()) {
            val p = EndpointPair()
            val c = p.connect(quicConfig { congestionController = factory })
            p.use { _ ->
                assertTrue(p.confirmed(c))
                val cc = c.path.cc
                val t0 = p.now
                ce(c, t0, t0 - 5.milliseconds) // recovery period from t0
                cc.onLoss(t0 + 100.milliseconds, 0, t0 + 50.milliseconds, true) // persistent congestion: recovery over, minimum window
                // slow start again on packets sent after it
                repeat(20) { cc.onAck(t0 + 150.milliseconds, t0 + 120.milliseconds, 1200, 20.milliseconds, false) }
                val grown = cc.cwnd
                val events = c.stats.ecnCeEvents
                ce(c, t0 + 200.milliseconds, t0 - 1.milliseconds) // sent before the old recovery start: no recovery period now
                assertTrue(cc.cwnd < grown, "$name: the CE after persistent congestion reduces: ${cc.cwnd} vs $grown")
                assertEquals(events + 1, c.stats.ecnCeEvents, "$name: one congestion event")
            }
        }
    }

    /** RFC 9002 appendix B.5-B.8 NewReno, written from the pseudocode (integer congestion avoidance with the remainder carried). */
    private class B6Model(
        var cwnd: Long,
        var ssthresh: Long,
        private val mds: Long = 1200,
    ) {
        var recoveryStart: TimeMark? = null // congestion_recovery_start_time; null is 0
        private var carry = 0L
        var events = 0

        fun inCongestionRecovery(sent: TimeMark): Boolean = recoveryStart.let { it != null && sent <= it }

        fun onCongestionEvent(
            now: TimeMark,
            sent: TimeMark,
        ): Boolean {
            if (inCongestionRecovery(sent)) return false
            recoveryStart = now
            ssthresh = cwnd / 2
            cwnd = maxOf(ssthresh, 2 * mds)
            ssthresh = cwnd
            carry = 0
            return true
        }

        fun onLoss(
            now: TimeMark,
            sent: TimeMark,
            persistent: Boolean,
        ) {
            onCongestionEvent(now, sent)
            if (persistent) {
                cwnd = 2 * mds
                recoveryStart = null
            }
        }

        fun onCe(
            now: TimeMark,
            sent: TimeMark,
        ) {
            if (onCongestionEvent(now, sent)) events++
        }

        fun onAck(
            sent: TimeMark,
            bytes: Int,
        ) {
            if (inCongestionRecovery(sent)) return
            if (cwnd < ssthresh) {
                cwnd += bytes
            } else {
                carry += mds * bytes
                if (carry >= cwnd) {
                    val g = carry / cwnd
                    carry -= g * cwnd
                    cwnd += g
                }
            }
        }
    }

    /**
     * Property: on every path, for random interleavings of losses, persistent congestion, CE reports through the core and
     * acknowledgments, with send times before and after each recovery start, NewReno's window, threshold and the CE congestion
     * events equal an appendix B model's; CUBIC's CE congestion events equal the model's event decisions.
     */
    @Test fun ceAndLossShareOneRecoveryPeriodAgainstAppendixBModel() {
        for ((name, factory) in controllers()) {
            for (seed in 0 until 60) {
                val rnd = Random(seed)
                val p = EndpointPair()
                val c = p.connect(quicConfig { congestionController = factory })
                p.use { _ ->
                    assertTrue(p.confirmed(c))
                    val other = c.addPath(InetSocketAddress("10.0.0.2", 443), p.now, PathId(7))
                    val ids = listOf(c.path.id, other)
                    val ccs = ids.associateWith { c.paths.byId(it)!!.cc }
                    // the handshake's acknowledgments grew the window in slow start, with no congestion event yet
                    val models =
                        ids.associateWith {
                            B6Model(
                                ccs.getValue(it).cwnd,
                                (ccs.getValue(it) as? NewReno)?.ssthresh ?: Long.MAX_VALUE,
                            )
                        }
                    var now = p.now
                    val ceEvents0 = c.stats.ecnCeEvents
                    repeat(60) { step ->
                        now += (1 + rnd.nextInt(30)).milliseconds
                        val id = ids[rnd.nextInt(ids.size)]
                        val m = models.getValue(id)
                        val cc = ccs.getValue(id)
                        val sent = now - rnd.nextInt(0, 80).milliseconds
                        val what =
                            when (rnd.nextInt(10)) {
                                in 0..3 -> {
                                    ce(c, now, sent, id)
                                    m.onCe(now, sent)
                                    "ce"
                                }

                                in 4..5 -> {
                                    cc.onLoss(now, 0, sent, false)
                                    m.onLoss(now, sent, false)
                                    "loss"
                                }

                                6 -> {
                                    cc.onLoss(now, 0, sent, true)
                                    m.onLoss(now, sent, true)
                                    "persistent"
                                }

                                else -> {
                                    val bytes = 1 + rnd.nextInt(1200)
                                    cc.onAck(now, sent, bytes, 20.milliseconds, false)
                                    m.onAck(sent, bytes)
                                    "ack"
                                }
                            }
                        val at = "$name seed $seed step $step ($what on $id)"
                        if (cc is NewReno) {
                            assertEquals(m.cwnd, cc.cwnd, "$at: cwnd")
                            assertEquals(m.ssthresh, cc.ssthresh, "$at: ssthresh")
                        }
                        assertEquals(
                            models.values.sumOf { it.events }.toLong(),
                            c.stats.ecnCeEvents - ceEvents0,
                            "$at: CE congestion events",
                        )
                    }
                }
            }
        }
    }
}
