// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h2

import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** The HTTP/2 client signal the application sees (RFC 9218 section 7: the most recently received PRIORITY_UPDATE wins). */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class ClientSignalTest {
    @Test fun followsUpdatesInOrder() {
        val s = ClientSignal(StreamPriority.Default)
        s.signal(1, false, seq = 1)
        s.signal(6, true, seq = 2)
        assertEquals(StreamPriority(6, true), s.flow.value)
    }

    /**
     * A signal that overtook an older one keeps its place: the older one, delivered late, is dropped, and a collector never
     * sees the flow go back to it (seq 2, then seq 1 late, then seq 3).
     */
    @Test fun negative_staleSignalIsDropped() =
        runTest {
            val s = ClientSignal(StreamPriority.Default)
            val seen = ArrayList<StreamPriority>()
            val job = launch(UnconfinedTestDispatcher(testScheduler)) { s.flow.collect { seen += it } }
            s.signal(2, false, seq = 2)
            assertEquals(StreamPriority(2), s.flow.value)
            s.signal(5, true, seq = 1)
            assertEquals(StreamPriority(2), s.flow.value)
            s.signal(6, false, seq = 3)
            job.cancel()
            assertEquals(listOf(StreamPriority.Default, StreamPriority(2), StreamPriority(6)), seen)
        }

    /** Values parse as a complete set: a parameter left out is its default, a value that fails to parse means the defaults. */
    @Test fun parsesACompleteSet() {
        val s = ClientSignal(StreamPriority(5, true))
        assertEquals(2 * 1, s.parse("u=1"))
        assertEquals(2 * 3 + 1, s.parse("i"))
        assertEquals(2 * 3, s.parse("U=1"))
    }
}
