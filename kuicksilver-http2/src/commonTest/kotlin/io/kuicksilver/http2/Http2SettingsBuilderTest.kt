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

    /**
     * Self-attack on the Rapid Reset defence (CVE-2023-44487): a budget beyond 100 times nghttp2's would let a flood through,
     * so the flood budgets have a ceiling; the ceiling itself is accepted.
     */
    @Test fun negative_floodBudgetsAboveTheirCeilingAreRefused() {
        for (bad in listOf(RateLimit(3_301, 1_000), RateLimit(33, 100_001), RateLimit(Int.MAX_VALUE, Int.MAX_VALUE))) {
            val e = assertFailsWith<IllegalArgumentException>("$bad") { http2Settings { floodLimits { resets = bad } } }
            assertEquals(
                "floodLimits { resets } must be at most RateLimit(perSecond=3300, burst=100000): a larger budget no longer bounds " +
                    "Rapid Reset (CVE-2023-44487), got $bad",
                e.message,
            )
        }
        val g = assertFailsWith<IllegalArgumentException> { http2Settings { floodLimits { glitches = RateLimit(33_001, 10) } } }
        assertTrue(g.message.orEmpty().startsWith("floodLimits { glitches } must be at most"), g.message)
        val top =
            http2Settings {
                floodLimits {
                    resets = Http2Settings.Builder.FloodLimits.MAX_RESETS
                    glitches = Http2Settings.Builder.FloodLimits.MAX_GLITCHES
                }
            }
        assertEquals(3_300, top.resetsPerSecond)
        assertEquals(100_000, top.resetBurst)
    }

    /**
     * Self-attack on the count limits: a CONTINUATION or control-frame limit beyond its ceiling would no longer bound a flood,
     * so it is refused like a negative one; the ceilings themselves are accepted.
     */
    @Test fun negative_countLimitsAboveTheirCeilingAreRefused() {
        for (bad in listOf(-1, 801, Int.MAX_VALUE)) {
            val e = assertFailsWith<IllegalArgumentException>("$bad") { http2Settings { floodLimits { maxContinuationFrames = bad } } }
            assertEquals(
                "floodLimits { maxContinuationFrames } must be 0..800: more no longer bounds a CONTINUATION flood (CVE-2024-27316), " +
                    "got $bad",
                e.message,
            )
        }
        for (bad in listOf(0, 100_001, Int.MAX_VALUE)) {
            val e = assertFailsWith<IllegalArgumentException>("$bad") { http2Settings { floodLimits { maxControlFramesQueued = bad } } }
            assertEquals(
                "floodLimits { maxControlFramesQueued } must be 1..100000: more lets a peer that never reads hold that much " +
                    "memory, got $bad",
                e.message,
            )
        }
        for (bad in listOf(-1, 10_001, Int.MAX_VALUE)) {
            val e = assertFailsWith<IllegalArgumentException>("$bad") { http2Settings { floodLimits { maxEmptyFrames = bad } } }
            assertEquals(
                "floodLimits { maxEmptyFrames } must be 0..10000: more no longer bounds an empty-frame flood (CVE-2019-9518), " +
                    "got $bad",
                e.message,
            )
        }
        val top =
            http2Settings {
                floodLimits {
                    maxContinuationFrames = Http2Settings.Builder.FloodLimits.MAX_CONTINUATION_FRAMES
                    maxControlFramesQueued = Http2Settings.Builder.FloodLimits.MAX_CONTROL_FRAMES_QUEUED
                    maxEmptyFrames = Http2Settings.Builder.FloodLimits.MAX_EMPTY_FRAMES
                }
            }
        assertEquals(800, top.maxContinuationFrames)
        assertEquals(100_000, top.maxControlFramesQueued)
        assertEquals(10_000, top.maxEmptyFrames)
        // zero tolerance stays possible: the first empty DATA frame ends the connection
        assertEquals(0, http2Settings { floodLimits { maxEmptyFrames = 0 } }.maxEmptyFrames)
    }
}
