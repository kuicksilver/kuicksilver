// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TransportErrorTest {
    /** RFC 9000 section 20.1, the transport error codes on the wire, and RFC 9368 section 10.2.1 for VERSION_NEGOTIATION_ERROR. */
    @Test fun codesMatchTheRfcRegistry() {
        val expected =
            listOf(
                TransportError.NO_ERROR to 0x00L,
                TransportError.INTERNAL_ERROR to 0x01L,
                TransportError.CONNECTION_REFUSED to 0x02L,
                TransportError.FLOW_CONTROL_ERROR to 0x03L,
                TransportError.STREAM_LIMIT_ERROR to 0x04L,
                TransportError.STREAM_STATE_ERROR to 0x05L,
                TransportError.FINAL_SIZE_ERROR to 0x06L,
                TransportError.FRAME_ENCODING_ERROR to 0x07L,
                TransportError.TRANSPORT_PARAMETER_ERROR to 0x08L,
                TransportError.CONNECTION_ID_LIMIT_ERROR to 0x09L,
                TransportError.PROTOCOL_VIOLATION to 0x0aL,
                TransportError.INVALID_TOKEN to 0x0bL,
                TransportError.APPLICATION_ERROR to 0x0cL,
                TransportError.CRYPTO_BUFFER_EXCEEDED to 0x0dL,
                TransportError.KEY_UPDATE_ERROR to 0x0eL,
                TransportError.AEAD_LIMIT_REACHED to 0x0fL,
                TransportError.NO_VIABLE_PATH to 0x10L,
                TransportError.VERSION_NEGOTIATION_ERROR to 0x11L,
            )
        for ((i, pair) in expected.withIndex()) assertEquals(pair.second, pair.first, "code #$i")
    }

    /** RFC 9000 section 20.1: CRYPTO_ERROR is 0x0100-0x01ff, the low byte the TLS alert (RFC 9001 section 4.8). */
    @Test fun cryptoErrorRange() {
        assertEquals(0x0100L, TransportError.CRYPTO_ERROR_BASE)
        assertEquals(0x0100L, TransportError.crypto(0))
        assertEquals(0x012aL, TransportError.crypto(42)) // bad_certificate
        assertEquals(0x01ffL, TransportError.crypto(255))
        assertFailsWith<IllegalArgumentException> { TransportError.crypto(256) }
        assertFailsWith<IllegalArgumentException> { TransportError.crypto(-1) }
    }
}
