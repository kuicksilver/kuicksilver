// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.crypto.NullPacketProtector
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.PacketProtector
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.milliseconds

/**
 * RFC 9001 section 6.4: "Packets with higher packet numbers MUST be protected with either the same or newer packet protection keys
 * than packets with lower packet numbers. An endpoint that successfully removes protection with old keys when newer keys were used
 * for packets with lower packet numbers MUST treat this as a connection error of type KEY_UPDATE_ERROR." Every order of arrival, and
 * section 6.2's acknowledgment carried with old keys.
 */
class KeyPhaseOrderingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val pto = 100.milliseconds
    private val now = TimeMark(0)

    private class Gen(
        val gen: Int,
    ) : PacketProtector by NullPacketProtector {
        override fun next(): PacketProtector = Gen(gen + 1)

        override fun close() {}
    }

    private fun keyPhase() = KeyPhase(Gen(0), Gen(0)) { _, _ -> }

    private fun KeyPhase.receive(
        phase: Int,
        pn: Long,
    ) {
        readKey(phase == 1, pn)
        onAuthenticated(phase == 1, pn, now, pto)
    }

    private fun assertKeyUpdateError(block: () -> Unit) {
        val e = assertFailsWith<QuicWireException> { block() }
        assertEquals(TransportError.KEY_UPDATE_ERROR, e.code, e.message)
    }

    /** The peer's update at pn 20; then a packet of the new phase below a reordered old-phase packet that was opened first. */
    @Test fun negative_newPhaseBelowReorderedPreviousPhasePacket() {
        val kp = keyPhase()
        kp.receive(0, 10)
        kp.receive(1, 20) // the peer's update
        kp.receive(0, 15) // reordered, previous keys: fine so far (15 < 20)
        assertKeyUpdateError { kp.receive(1, 12) } // newer keys on 12, older on 15
    }

    /** Lowering the current phase's lowest packet number must not let a packet of the new phase slip under an old one. */
    @Test fun negative_currentPhaseLoweredBelowAnOldPacket() {
        val kp = keyPhase()
        kp.receive(0, 10)
        kp.receive(1, 20)
        assertKeyUpdateError { kp.receive(1, 5) } // newer keys on 5, older on 10
    }

    /** Two generations back: the previous key opens a packet number below one the generation before it opened. */
    @Test fun negative_previousKeyBelowAnOlderGeneration() {
        val kp = keyPhase()
        kp.receive(0, 10)
        kp.receive(1, 20)
        kp.onAckSent() // we acknowledged a packet of phase 1: the peer may update again
        kp.receive(0, 30) // generation 2
        assertEquals(2L, kp.generation)
        assertKeyUpdateError { kp.receive(1, 5) } // generation 1 on 5 (previous keys), generation 0 on 10
    }

    /** A packet number opened with the current keys and then, as a reuse, with the next ones (RFC 9000 section 12.3, not 6.4). */
    @Test fun negative_samePacketNumberUnderNewerKeys() {
        val kp = keyPhase()
        kp.receive(0, 10)
        assertKeyUpdateError { kp.receive(1, 10) }
    }

    /** Our own update: the peer's late old-phase packet 30 and then its new-phase packet 25 (the order the red-team case used). */
    @Test fun negative_afterOwnUpdateNewPhaseBelowOldPacket() {
        val kp = keyPhase()
        kp.onPacketSent(0)
        kp.onPacketAcked(0, now)
        kp.receive(0, 10)
        check(kp.initiate(now, pto))
        kp.receive(0, 30)
        assertKeyUpdateError { kp.receive(1, 25) }
    }

    /** Our own update, the other order: the new phase at 25 first; an old-phase 30 is then tried with the next keys and fails. */
    @Test fun negative_afterOwnUpdateOldPacketAboveNewPhaseIsNotOpenedWithOldKeys() {
        val kp = keyPhase()
        kp.onPacketSent(0)
        kp.onPacketAcked(0, now)
        kp.receive(0, 10)
        check(kp.initiate(now, pto))
        kp.receive(1, 25)
        // 30 is above the current phase: the next keys (section 6.5), never the old ones; with null protection they "open" it, so
        // the update it would start is refused: 30 under next keys while we acknowledged nothing of phase 1
        assertEquals(2, (kp.readKey(false, 30) as Gen).gen, "the next keys")
        assertEquals(0, (kp.readKey(false, 20) as Gen).gen, "below the new phase: the previous keys")
        assertKeyUpdateError { kp.receive(0, 30) }
    }

    /** Honest reordering around an update is no error: old-phase packets below the first new-phase one, in any order. */
    @Test fun reorderedPacketsAroundAnUpdateAreFine() {
        val kp = keyPhase()
        for (pn in listOf(3L, 1L, 2L)) kp.receive(0, pn)
        kp.receive(1, 9)
        for (pn in listOf(6L, 4L, 8L, 5L)) kp.receive(0, pn) // previous keys
        for (pn in listOf(12L, 10L, 11L)) kp.receive(1, pn)
        kp.receive(0, 7) // still below every new-phase packet number
        assertEquals(1L, kp.generation)
    }

    /** Section 6.2 (MAY, taken): an ACK of a new-phase packet of ours in a packet the peer protected with the old keys. */
    @Test fun negative_ackOfNewPhaseCarriedWithOldKeys() {
        val kp = keyPhase()
        kp.onPacketSent(0)
        kp.onPacketAcked(0, now)
        kp.receive(0, 10)
        check(kp.initiate(now, pto))
        kp.onPacketSent(1) // our first packet of phase 1
        kp.receive(0, 11) // previous keys
        kp.checkAckInPacket(0, 0x02) // an acknowledgment of a phase-0 packet: fine
        assertKeyUpdateError { kp.checkAckInPacket(1, 0x02) }
    }

    @Test fun ackOfNewPhaseCarriedWithNewKeysIsFine() {
        val kp = keyPhase()
        kp.onPacketSent(0)
        kp.onPacketAcked(0, now)
        kp.receive(0, 10)
        check(kp.initiate(now, pto))
        kp.onPacketSent(1)
        kp.receive(1, 12)
        kp.checkAckInPacket(1, 0x02)
        kp.receive(0, 11) // a reordered old-phase packet without an ACK of phase 1 is fine too
        kp.checkAckInPacket(0, 0x02)
    }
}
