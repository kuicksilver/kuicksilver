// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h3

import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [h3FailureFacts]'s `refusedUnconfirmed`: a request failed on a connection that ended with a CRYPTO_ERROR (0x0100 to
 * 0x01ff, RFC 9001 section 4.8) before its handshake was confirmed was not processed (RFC 9001 section 5.7: a server "MUST
 * NOT process incoming 1-RTT protected packets before the TLS handshake is complete"), so it may go over TCP whatever its
 * method. A confirmed connection, another error code, an unknown confirmation and a cancellation are not that.
 */
class H3FailureFactsTest {
    private fun closed(
        code: Long,
        initiator: Initiator = Initiator.Peer,
    ) = QuicException.ConnectionLost.TransportClosed(code, 0, "", ByteArray(0), initiator)

    @Test fun aCryptoErrorBeforeConfirmationIsARefusedHandshake() {
        val end = closed(0x0174) // certificate_required
        assertTrue(h3FailureFacts(end, end, handshakeConfirmed = false).refusedUnconfirmed)
        assertTrue(h3FailureFacts(end, closed(0x0100), handshakeConfirmed = false).refusedUnconfirmed)
        assertTrue(h3FailureFacts(end, closed(0x01ff), handshakeConfirmed = false).refusedUnconfirmed)
    }

    @Test fun negative_aConfirmedConnectionOrAnotherCodeIsNot() {
        val end = closed(0x0174)
        assertFalse(h3FailureFacts(end, end, handshakeConfirmed = true).refusedUnconfirmed, "confirmed: HANDSHAKE_DONE came")
        assertFalse(h3FailureFacts(end, end, handshakeConfirmed = null).refusedUnconfirmed, "not known")
        assertFalse(h3FailureFacts(end, closed(0x0200), handshakeConfirmed = false).refusedUnconfirmed, "above CRYPTO_ERROR")
        assertFalse(h3FailureFacts(end, closed(0x00ff), handshakeConfirmed = false).refusedUnconfirmed, "below CRYPTO_ERROR")
        assertFalse(h3FailureFacts(end, closed(0x0a), handshakeConfirmed = false).refusedUnconfirmed, "PROTOCOL_VIOLATION")
        // this side's CRYPTO_ERROR (a NewSessionTicket it rejects) may come after the server processed the request
        assertFalse(h3FailureFacts(end, closed(0x0174, Initiator.Local), handshakeConfirmed = false).refusedUnconfirmed, "local")
        // 0-RTT the server accepted may have been processed before the handshake completed (RFC 9001 section 4.6)
        assertFalse(
            h3FailureFacts(end, end, handshakeConfirmed = false, earlyDataAccepted = true).refusedUnconfirmed,
            "0-RTT accepted",
        )
        assertTrue(h3FailureFacts(end, end, handshakeConfirmed = false, earlyDataAccepted = false).refusedUnconfirmed, "0-RTT refused")
        val cancelled = kotlinx.coroutines.CancellationException("cancelled")
        assertFalse(h3FailureFacts(cancelled, end, handshakeConfirmed = false).refusedUnconfirmed, "a cancellation")
    }
}
