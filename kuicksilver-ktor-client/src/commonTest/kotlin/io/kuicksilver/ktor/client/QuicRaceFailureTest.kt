// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.h3.quicRaceFailure
import io.kuicksilver.ktor.client.h3.withAttempts
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/**
 * What a QUIC address race reports when every attempt failed: a refusal (no broken mark, RFC 7838 section 2.4) only when
 * every address refused, the attempts' failures kept with a timeout.
 */
class QuicRaceFailureTest {
    private fun refused() =
        QuicException.ConnectionLost.TransportClosed(TransportError.CONNECTION_REFUSED, 0, "", ByteArray(0), Initiator.Peer)

    private fun closed() = QuicException.ConnectionLost.TransportClosed(0xa, 0, "", ByteArray(0), Initiator.Peer)

    @Test fun everyAddressRefusedIsARefusal() {
        val a = refused()
        val b = refused()
        assertSame(b, quicRaceFailure(listOf(a, b)))
    }

    @Test fun negative_oneAddressThatDidNotRefuseDecides() {
        // in either order: the result does not depend on which attempt failed last
        val other = closed()
        assertSame(other, quicRaceFailure(listOf(refused(), other)))
        assertSame(other, quicRaceFailure(listOf(other, refused())))
    }

    @Test fun aTimeoutCarriesEveryAttempt() {
        val attempts = listOf(refused(), closed())
        val t = IllegalStateException("timed out").withAttempts(attempts + attempts.first())
        assertEquals(attempts, t.suppressedExceptions)
    }
}
