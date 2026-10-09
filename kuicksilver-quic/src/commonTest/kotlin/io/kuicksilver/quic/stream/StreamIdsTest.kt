// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.tls.TlsRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StreamIdsTest {
    @Test fun idBitsRfc9000Section2_1() {
        assertTrue(StreamIds.isClientInitiated(0) && StreamIds.isBidi(0))
        assertFalse(StreamIds.isClientInitiated(1))
        assertTrue(StreamIds.isBidi(1))
        assertTrue(StreamIds.isClientInitiated(2) && !StreamIds.isBidi(2))
        assertFalse(StreamIds.isClientInitiated(3) || StreamIds.isBidi(3))
        assertEquals(400L, StreamIds.of(TlsRole.Client, bidi = true, index = 100))
        assertEquals(100L, StreamIds.index(400))
        assertEquals(7L, StreamIds.of(TlsRole.Server, bidi = false, index = 1))
    }
}
