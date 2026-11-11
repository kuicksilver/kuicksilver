// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CongestionController
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.recovery.SpaceId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/**
 * RFC 9002 section 7: "An endpoint MUST NOT send a packet if it would cause bytes_in_flight ... to be larger than the congestion
 * window, unless the packet is sent on a PTO timer expiration (see Section 6.2) or when entering recovery"; section 7.5: "Probe
 * packets MUST NOT be blocked by the congestion controller".
 */
@OptIn(ExperimentalKuicksilverApi::class)
class CongestionWindowTest {
    /** A window that never moves, [rate] bytes per second of pacing, [quantum] bytes per burst. */
    private class FixedWindow(
        override val cwnd: Long,
        private val rate: Long = 10_000_000_000L,
        override val sendQuantum: Int = 65_536,
    ) : CongestionController {
        override var bytesInFlight: Long = 0
            private set

        override fun onPacketSent(
            now: TimeMark,
            bytes: Int,
        ) {
            bytesInFlight += bytes
        }

        override fun onAck(
            now: TimeMark,
            sentTime: TimeMark,
            bytes: Int,
            smoothedRtt: Duration,
            appLimited: Boolean,
        ) {
            bytesInFlight -= bytes
        }

        override fun onLoss(
            now: TimeMark,
            lostBytes: Int,
            largestLostSentTime: TimeMark,
            persistentCongestion: Boolean,
        ) {
            bytesInFlight -= lostBytes
        }

        override fun onEcnCe(
            now: TimeMark,
            sentTime: TimeMark,
        ) {}

        override fun onMtuUpdate(maxDatagramSize: Int) {}

        override fun onDiscarded(bytes: Int) {
            bytesInFlight -= bytes
        }

        override fun pacingRate(smoothedRtt: Duration): Long = rate
    }

    private fun confirmedPair(cc: () -> CongestionController): CorePair {
        val p = CorePair(clientQuic = quicConfig { congestionController = cc })
        assertTrue(p.handshake())
        assertTrue(p.runUntil { p.client.state == ConnectionState.Confirmed })
        p.runUntil(200.milliseconds) { p.client.stats.bytesInFlight == 0L }
        return p
    }

    /** Writes far more than the window holds, then polls without delivering anything: what goes out must stay within [cwnd]. */
    private fun fillWindow(
        p: CorePair,
        c: ConnectionCore,
        batch: PacketBatch,
    ) {
        val id = c.openStream(true)
        c.writeStream(id, ByteArray(200_000), 0, 200_000, false)
        repeat(5) {
            batch.clear()
            c.poll(batch, p.now)
            assertTrue(
                c.cc.bytesInFlight <= c.cc.cwnd,
                "bytes in flight ${c.cc.bytesInFlight} above the window ${c.cc.cwnd} after poll $it",
            )
            p.advance(1.milliseconds)
        }
    }

    /**
     * A PTO probe still owed in a space when the space is discarded (a server's Initial probe that its anti-amplification budget
     * held back, then the client's Handshake packet) used to stay owed for ever, and every later datagram was treated as a probe,
     * outside the window.
     */
    @Test fun aProbeLeftInADiscardedSpaceDoesNotLiftTheWindow() {
        val p = CorePair(clientQuic = quicConfig { congestionController = { FixedWindow(12_000) } })
        val batch = PacketBatch(64)
        try {
            val c = p.client
            assertTrue(p.runUntil { c.writeKeys[2] != null && !c.spaceDiscarded[SpaceId.Handshake.ordinal] })
            c.probePending[SpaceId.Handshake.ordinal] = 2
            c.discardSpace(SpaceId.Handshake)
            assertEquals(0, c.probePending[SpaceId.Handshake.ordinal], "a discarded space owes no probe")
            assertTrue(p.handshake())
            assertTrue(p.runUntil { c.state == ConnectionState.Confirmed })
            p.runUntil(200.milliseconds) { c.stats.bytesInFlight == 0L }
            c.probePending[SpaceId.Initial.ordinal] = 1 // a count left behind in a space that is gone exempts nothing either
            fillWindow(p, c, batch)
        } finally {
            batch.close()
            p.close()
        }
    }
}
