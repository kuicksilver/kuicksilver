// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h2

import io.kuicksilver.quic.StreamPriority
import kotlin.test.Test
import kotlin.test.assertEquals

/** The HTTP/2 client signal the application sees (RFC 9218 section 7: the most recently received PRIORITY_UPDATE wins). */
class ClientSignalTest {
    @Test fun followsUpdatesInOrder() {
        val s = ClientSignal(StreamPriority.Default)
        s.signal(1, false, seq = 1)
        s.signal(6, true, seq = 2)
        assertEquals(StreamPriority(6, true), s.flow.value)
    }

    /** A signal that overtook an older one keeps its place: the older one, delivered late, is dropped. */
    @Test fun negative_staleSignalIsDropped() {
        val s = ClientSignal(StreamPriority.Default)
        s.signal(2, false, seq = 2)
        s.signal(5, true, seq = 1)
        assertEquals(StreamPriority(2), s.flow.value)
    }

    /** Values parse as a complete set: a parameter left out is its default, a value that fails to parse means the defaults. */
    @Test fun parsesACompleteSet() {
        val s = ClientSignal(StreamPriority(5, true))
        assertEquals(2 * 1, s.parse("u=1"))
        assertEquals(2 * 3 + 1, s.parse("i"))
        assertEquals(2 * 3, s.parse("U=1"))
    }
}
