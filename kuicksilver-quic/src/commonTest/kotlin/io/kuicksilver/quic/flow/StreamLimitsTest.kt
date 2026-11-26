// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.flow

import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StreamLimitsTest {
    @Test fun negative_streamLimit() {
        val l = StreamLimits(TlsRole.Server, 100, 100)
        for (i in 0 until 100) l.onPeerStream(4L * i) // client bidi streams 0, 4, ..., 396
        assertEquals(100L, l.peerStreamsOpened(bidi = true))
        val e = assertFailsWith<QuicWireException> { l.onPeerStream(400) }
        assertEquals(0x04L, e.code)
        assertEquals(100L, l.peerStreamsOpened(bidi = true))
    }

    @Test fun peerStreamLimitUni100() {
        val l = StreamLimits(TlsRole.Server, 100, 100)
        l.onPeerStream(4L * 99 + 2)
        assertEquals(
            0x04L,
            assertFailsWith<QuicWireException> {
                l.onPeerStream(4L * 100 + 2)
            }.code,
        )
    }

    @Test fun maxStreamsRaisedAfterHalfClosed() {
        val l = StreamLimits(TlsRole.Server, 100, 100)
        for (i in 0 until 100) l.onPeerStream(4L * i)
        for (i in 0 until 49) assertEquals(-1L, l.onPeerStreamClosed(bidi = true))
        assertEquals(150L, l.onPeerStreamClosed(bidi = true))
        l.onPeerStream(4L * 149)
        assertEquals(0x04L, assertFailsWith<QuicWireException> { l.onPeerStream(4L * 150) }.code)
    }

    @Test fun streamsBlockedWhenLocalLimitReached() {
        val l = StreamLimits(TlsRole.Client, 100, 100)
        assertFalse(l.canOpenLocal(bidi = true))
        assertEquals(0L, l.takeStreamsBlocked(bidi = true))
        assertEquals(-1L, l.takeStreamsBlocked(bidi = true))
        l.onPeerMaxStreams(bidi = true, max = 2)
        assertTrue(l.canOpenLocal(bidi = true))
        l.onLocalOpened(bidi = true)
        l.onLocalOpened(bidi = true)
        assertFalse(l.canOpenLocal(bidi = true))
        assertEquals(2L, l.takeStreamsBlocked(bidi = true))
        l.onPeerMaxStreams(bidi = true, max = 1)
        assertEquals(2L, l.peerMaxStreams(bidi = true), "limits never shrink")
    }

    @Test fun peerStreamOfWrongInitiatorIsStateError() {
        val l = StreamLimits(TlsRole.Server, 100, 100)
        assertEquals(0x05L, assertFailsWith<QuicWireException> { l.onPeerStream(1) }.code)
    }

    /** RFC 9000 section 19.11: a MAX_STREAMS value "cannot exceed 2^60"; the raise stops there and then sends nothing more. */
    @Test fun negative_maxStreamsNeverExceeds2Pow60() {
        val l = StreamLimits(TlsRole.Server, (1L shl 60) - 1, 100)
        l.onPeerStream(0)
        assertEquals(-1L, l.onPeerStreamClosed(bidi = true))
        assertEquals(1L shl 60, l.onPeerBlockedAtGranted(bidi = true), "1 closed + 2^60 - 1 is exactly the ceiling")
        l.onPeerStream(4)
        l.onPeerStreamClosed(bidi = true)
        assertEquals(-1L, l.onPeerBlockedAtGranted(bidi = true), "2 + 2^60 - 1 is clamped to the 2^60 already granted")
        assertEquals(1L shl 60, l.peerMaxStreamsGranted(bidi = true))
        // at the ceiling a full window of closes sends nothing either
        assertEquals(-1L, l.onPeerStreamClosed(bidi = true))
    }
}
