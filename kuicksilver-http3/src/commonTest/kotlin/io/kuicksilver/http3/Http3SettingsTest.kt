// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class Http3SettingsTest {
    /** The values the KDoc gives as defaults are defaults, not ceilings: larger values are accepted. */
    @Suppress("DEPRECATION") // maxInformationalResponses is deprecated and ignored, but its default must stay readable
    @Test
    fun documentedDefaultsAreNotCaps() {
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

    /**
     * RFC 9114 section 7.2.4.2: a server "MUST NOT accept 0-RTT data" unless the settings a client remembered are compatible
     * with its current ones. Every value of our SETTINGS frame (`H3Session.ourSettings`, GREASE aside) is part of the
     * context bound into our tickets, so a ticket issued under other SETTINGS gets no 0-RTT; options that never reach the
     * SETTINGS frame leave the tickets valid.
     */
    @Suppress("DEPRECATION") // maxInformationalResponses is not a setting either
    @Test
    fun earlyDataContextCoversEveryValueOfOurSettings() {
        val base = Http3Settings.Default.earlyDataContext().decodeToString()
        val sent =
            mapOf(
                "qpackMaxTableCapacity" to http3Settings { qpackMaxTableCapacity = 4096 },
                "qpackBlockedStreams" to http3Settings { qpackBlockedStreams = 16 },
                "maxFieldSectionSize" to http3Settings { maxFieldSectionSize = 1L shl 20 },
                "enableConnectProtocol" to http3Settings { enableConnectProtocol = true },
                "h3Datagram" to http3Settings { h3Datagram = false },
            )
        for ((name, changed) in sent) {
            assertNotEquals(base, changed.earlyDataContext().decodeToString(), "$name is not bound into the tickets")
        }
        // WebTransport's settings (WtSettings.ours) are fixed values, there whenever webTransport is on
        assertNotEquals(
            http3Settings { enableConnectProtocol = true }.earlyDataContext().decodeToString(),
            http3Settings {
                enableConnectProtocol = true
                webTransport = true
            }.earlyDataContext().decodeToString(),
        )
        val notSent =
            listOf(
                http3Settings { encoderMaxTableCapacity = 0 },
                http3Settings { grease = false },
                http3Settings { glitchProtection = false },
                http3Settings { maxEarlyPriorityUpdates = 0 },
                http3Settings { maxInformationalResponses = 0 },
                http3Settings { earlyData = Http3EarlyDataPolicy.Reject425() },
            )
        for (s in notSent) assertEquals(base, s.earlyDataContext().decodeToString())
    }

    @Suppress("DEPRECATION") // the deprecated maxInformationalResponses still validates its argument
    @Test
    fun refusalsNameTheOption() {
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
