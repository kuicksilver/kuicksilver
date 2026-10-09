// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

class QuicExceptionTest {
    @Test fun isKotlinxIoException() {
        val e: Throwable = QuicException.ConnectionLost.Timeout(TimeoutKind.Idle, 30.seconds)
        assertIs<IOException>(e)
        assertIs<QuicException.ConnectionLost>(e)
    }

    @Test fun createCopyKeepsFieldsAndCause() {
        val cause = IllegalStateException("boom")
        val e = QuicException.ConnectionLost.TransportClosed(0x0130L, null, "bad cert", byteArrayOf(1, 2), Initiator.Local, cause)
        val copy = e.createCopy()
        assertIs<QuicException.ConnectionLost.TransportClosed>(copy)
        assertEquals(0x0130L, copy.code)
        assertEquals("bad cert", copy.reason)
        assertEquals(Initiator.Local, copy.initiator)
        assertSame(cause, copy.cause)
        val r = QuicException.StreamError.Reset(4, 7, Initiator.Peer).createCopy()
        assertIs<QuicException.StreamError.Reset>(r)
        assertEquals(4, r.streamId)
        assertEquals(7, r.code)
    }

    @Test fun cryptoCodeIs0x0100PlusAlert() {
        assertEquals(0x0130L, TransportError.crypto(48))
        assertEquals(0x0178L, TransportError.crypto(120))
        assertEquals(0x0100L, TransportError.CRYPTO_ERROR_BASE)
    }
}
