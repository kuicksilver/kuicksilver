// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.crypto.NullPacketProtector
import io.kuicksilver.quic.wire.QuicWireException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.milliseconds

/**
 * RFC 9001 section 6.4: "Packets with higher packet numbers MUST be protected with either the same or newer packet
 * protection keys than packets with lower packet numbers. An endpoint that successfully removes protection with old keys
 * when newer keys were used for packets with lower packet numbers MUST treat this as a connection error of type
 * KEY_UPDATE_ERROR."
 */
class RedTeamKeyPhaseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val pto = 100.milliseconds

    /**
     * The peer protects pn 20 with the old keys and pn 15 with the new ones; pn 20 arrives first (reordering). When pn 15
     * then commits the update, the endpoint has successfully removed old-key protection from a packet above one the newer
     * keys protected: KEY_UPDATE_ERROR. The check compares pn 15 only with the LOWEST packet number of the old phase (10).
     */
    @Test fun negative_oldKeysAboveANewPhasePacketIsKeyUpdateError() {
        val kp = KeyPhase(NullPacketProtector, NullPacketProtector) { _, _ -> }
        val now = TimeMark(0)
        // phase 0: pn 10 and pn 20
        for (pn in listOf(10L, 20L)) {
            kp.readKey(false, pn)
            kp.onAuthenticated(false, pn, now, pto)
        }
        // phase 1 (the peer's update) with a lower packet number than the phase-0 packet already opened
        kp.readKey(true, 15)
        val e = assertFailsWith<QuicWireException> { kp.onAuthenticated(true, 15, now, pto) }
        assertEquals(TransportError.KEY_UPDATE_ERROR, e.code)
    }

    /** Same, for an update we initiated: the peer's pn 30 under the old keys was opened, then its pn 25 under the new ones. */
    @Test fun negative_oldKeysAboveANewPhasePacketAfterOurUpdateIsKeyUpdateError() {
        val kp = KeyPhase(NullPacketProtector, NullPacketProtector) { _, _ -> }
        val now = TimeMark(0)
        kp.onPacketSent(0)
        kp.onPacketAcked(0, now)
        kp.readKey(false, 10)
        kp.onAuthenticated(false, 10, now, pto)
        check(kp.initiate(now, pto))
        // the peer has not seen our update yet: pn 30 still in phase 0 (opened with the previous keys)
        kp.readKey(false, 30)
        kp.onAuthenticated(false, 30, now, pto)
        // then pn 25 in phase 1 arrives: newer keys below a packet opened with the old ones
        kp.readKey(true, 25)
        val e = assertFailsWith<QuicWireException> { kp.onAuthenticated(true, 25, now, pto) }
        assertEquals(TransportError.KEY_UPDATE_ERROR, e.code)
    }
}
