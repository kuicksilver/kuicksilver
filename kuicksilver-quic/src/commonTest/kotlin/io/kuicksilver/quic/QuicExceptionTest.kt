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

    @Test fun frameTypeIsNonNull() {
        // 0.2.0: the frame type is always known (0 when no frame triggered the error), so the API no longer makes callers handle null
        val ft: Long = QuicException.ConnectionLost.TransportClosed(0x0a, 0x06, "", ByteArray(0), Initiator.Peer).frameType
        assertEquals(0x06L, ft)
    }

    @Test fun createCopyKeepsFieldsAndCause() {
        val cause = IllegalStateException("boom")
        val e = QuicException.ConnectionLost.TransportClosed(0x0130L, 0L, "bad cert", byteArrayOf(1, 2), Initiator.Local, cause)
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

    /** What a layer above attached as suppressed (a client engine's call diagnostics) survives the coroutines' copy. */
    @Test fun createCopyKeepsTheSuppressed() {
        val attached = IllegalStateException("attached above")
        val copies =
            listOf<QuicException>(
                QuicException.ConnectionLost.Timeout(TimeoutKind.Handshake, 1.seconds),
                QuicException.ConnectionLost.TransportClosed(0x0130L, 0L, "", ByteArray(0), Initiator.Peer),
                QuicException.ConnectionLost.ApplicationClosed(0, "", Initiator.Peer),
                QuicException.ConnectionLost.StatelessReset(),
                QuicException.StreamError.Reset(4, 7, Initiator.Peer),
                QuicException.DontFragmentUnavailable(IpFamily.V4, "test", permanent = false),
                QuicException.EndpointClosing(),
            ).map { e ->
                e.addSuppressed(attached)
                e.createCopy()
            }
        for (c in copies) assertSame(attached, c!!.suppressedExceptions.single(), "$c")
    }

    @Test fun cryptoCodeIs0x0100PlusAlert() {
        assertEquals(0x0130L, TransportError.crypto(48))
        assertEquals(0x0178L, TransportError.crypto(120))
        assertEquals(0x0100L, TransportError.CRYPTO_ERROR_BASE)
    }
}
