// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.http2

import io.kuicksilver.config.RateLimit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The Http2Settings builder (ADR-0026): every option reaches the settings, ranges are named, and the defaults hold. */
class Http2SettingsBuilderTest {
    @Test fun everyOptionReachesTheSettings() {
        val s =
            http2Settings {
                headerTableSize = 100
                maxConcurrentStreams = 7
                initialStreamWindow = 70_000
                maxStreamWindow = 80_000
                initialConnectionWindow = 90_000
                maxConnectionWindow = 100_000
                maxFrameSize = 20_000
                maxFieldSectionSize = 30_000
                settingsAckTimeout = 3.seconds
                maxHeaderBlockTime = 4.seconds
                floodLimits {
                    maxContinuationFrames = 2
                    maxControlFramesQueued = 3
                    maxEmptyFrames = 4
                    resets = RateLimit(5, 6)
                    glitches = RateLimit(7, 8)
                }
            }
        for (x in listOf(s, s.toBuilder().build())) {
            assertEquals(100, x.headerTableSize)
            assertEquals(7, x.maxConcurrentStreams)
            assertEquals(70_000, x.initialStreamWindow)
            assertEquals(80_000, x.maxStreamWindow)
            assertEquals(90_000, x.initialConnectionWindow)
            assertEquals(100_000, x.maxConnectionWindow)
            assertEquals(20_000, x.maxFrameSize)
            assertEquals(30_000, x.maxHeaderListSize)
            assertEquals(3.seconds, x.settingsAckTimeout)
            assertEquals(4.seconds, x.maxHeaderBlockTime)
            assertEquals(2, x.maxContinuationFrames)
            assertEquals(3, x.maxControlFramesQueued)
            assertEquals(4, x.maxEmptyFrames)
            assertEquals(5, x.resetsPerSecond)
            assertEquals(6, x.resetBurst)
            assertEquals(7, x.glitchesPerSecond)
            assertEquals(8, x.glitchBurst)
        }
    }

    @Test fun defaultsAreTheDocumentedOnes() {
        val d = Http2Settings.Default
        assertEquals(4_096, d.headerTableSize)
        assertEquals(100, d.maxConcurrentStreams)
        assertEquals(65_536, d.maxHeaderListSize)
        assertEquals(33, d.resetsPerSecond)
        assertEquals(1_000, d.resetBurst)
        assertEquals(330, d.glitchesPerSecond)
        assertEquals(10_000, d.glitchBurst)
    }

    /** A Long beyond what the wire field holds is refused by name, never truncated to an Int. */
    @Test fun negative_valuesBeyondTheWireRangeAreRefusedByName() {
        val e = assertFailsWith<IllegalArgumentException> { http2Settings { initialStreamWindow = 1L shl 31 } }
        assertTrue("initialStreamWindow" in e.message.orEmpty(), e.message)
        val f = assertFailsWith<IllegalArgumentException> { http2Settings { maxConcurrentStreams = -1 } }
        assertTrue("maxConcurrentStreams" in f.message.orEmpty(), f.message)
        val g = assertFailsWith<IllegalArgumentException> { http2Settings { floodLimits { maxControlFramesQueued = 0 } } }
        assertTrue("floodLimits { maxControlFramesQueued }" in g.message.orEmpty(), g.message)
    }
}
