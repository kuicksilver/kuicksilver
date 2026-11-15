// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

class ConnectionCoreGapsTest {
    /**
     * RFC 9000 section 10.2.2: "An endpoint that has entered the draining state MUST NOT send any packets"; a local close requested
     * while draining changes nothing either (the connection already ended with the peer's reason, reported once).
     */
    @Test fun negative_drainingConnectionSendsNothingAndIgnoresALocalClose() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.server!!.close(7, "bye", p.now)
            assertTrue(p.runUntil(1000.milliseconds) { p.closedReason(p.clientEvents) != null })
            assertEquals(ConnectionState.Draining, p.client.state)
            val drainUntil = assertNotNull(p.client.timers.closeDeadline)
            assertTrue(drainUntil > p.now + 3.milliseconds, "RFC 9000 10.2: draining lasts three PTO; until $drainUntil, now ${p.now}")
            p.client.close(9, "late", p.now)
            assertEquals(ConnectionState.Draining, p.client.state)
            val out = PacketBatch(4)
            try {
                assertEquals(0, p.client.poll(out, p.now + 1.milliseconds), "nothing leaves a draining endpoint")
            } finally {
                out.close()
            }
            p.drainEvents(p.client, p.clientEvents)
            assertEquals(1, p.clientEvents.count { it is ConnectionEvent.Closed })
            assertEquals(7L, assertIs<QuicException.ConnectionLost.ApplicationClosed>(p.closedReason(p.clientEvents)).code)
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 10.2: "The closing and draining connection states ... SHOULD persist for at least three times the current PTO". */
    @Test fun negative_closingStateEndsInTheFuture() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.close(0, "", p.now)
            assertEquals(ConnectionState.Closing, p.client.state)
            val until = assertNotNull(p.client.timers.closeDeadline)
            assertTrue(until > p.now + 3.milliseconds, "closing until $until, now ${p.now}")
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 20.1: only codes 0x0100-0x01ff carry a TLS alert ("CRYPTO_ERROR"); a PROTOCOL_VIOLATION from the peer has no TLS cause. */
    @Test fun negative_peerTransportCloseOutsideTheCryptoRangeHasNoTlsCause() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            p.client.testInjectFrames += ONE_RTT to byteArrayOf(0x1c, 0x0a, 0x00, 0x00) // CONNECTION_CLOSE PROTOCOL_VIOLATION, no reason
            assertTrue(p.runUntil(1000.milliseconds) { p.closedReason(p.serverEvents) != null })
            val r = assertIs<QuicException.ConnectionLost.TransportClosed>(p.closedReason(p.serverEvents))
            assertEquals(0x0aL, r.code)
            assertNull(r.cause)
        } finally {
            p.close()
        }
    }

    /** A peer's reason phrase of exactly 1024 bytes is kept whole (the cut is only above 1 KiB). */
    @Test fun negative_peerReasonOfExactly1024BytesIsKept() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            val frame = byteArrayOf(0x1d, 0x05, 0x44, 0x00) + ByteArray(1024) { 'r'.code.toByte() } // application close, code 5
            p.client.testInjectFrames += ONE_RTT to frame
            assertTrue(p.runUntil(1000.milliseconds) { p.closedReason(p.serverEvents) != null })
            val r = assertIs<QuicException.ConnectionLost.ApplicationClosed>(p.closedReason(p.serverEvents))
            assertEquals(1024, r.reason.length)
        } finally {
            p.close()
        }
    }

    /** RFC 9000 section 19.19: the Error Code is a variable-length integer; 2^62 cannot be encoded and is refused up front. */
    @Test fun negative_closeRefusesAnErrorCodeAbove2Pow62Minus1() {
        val p = CorePair()
        try {
            assertTrue(p.handshake())
            assertFailsWith<IllegalArgumentException> { p.client.close(1L shl 62, "", p.now) }
            p.client.close((1L shl 62) - 1, "", p.now)
            assertEquals(ConnectionState.Closing, p.client.state)
        } finally {
            p.close()
        }
    }

    private companion object {
        /** The 1-RTT level of `ConnectionCore.testInjectFrames`. */
        const val ONE_RTT = 3
    }
}
