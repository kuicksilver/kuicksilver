// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Http3SettingsTest {
    /** The values the KDoc gives as defaults are defaults, not ceilings: larger values are accepted. */
    @Test fun documentedDefaultsAreNotCaps() {
        val d = Http3Settings.Default
        assertEquals(4096L, d.encoderMaxTableCapacity)
        assertEquals(65_536L, d.maxFieldSectionSize)
        assertEquals(5, d.maxInformationalResponses)
        assertEquals(32, d.maxEarlyPriorityUpdates)
        val big =
            http3Settings {
                encoderMaxTableCapacity = 1L shl 20
                maxFieldSectionSize = 1L shl 20
                maxEarlyPriorityUpdates = 1000
            }
        assertEquals(1000, big.maxEarlyPriorityUpdates)
    }

    @Test fun refusalsNameTheOption() {
        assertEquals(
            "maxInformationalResponses must not be negative",
            assertFailsWith<IllegalArgumentException> { http3Settings { maxInformationalResponses = -1 } }.message,
        )
        assertEquals(
            "maxEarlyPriorityUpdates must not be negative",
            assertFailsWith<IllegalArgumentException> { http3Settings { maxEarlyPriorityUpdates = -1 } }.message,
        )
    }
}
