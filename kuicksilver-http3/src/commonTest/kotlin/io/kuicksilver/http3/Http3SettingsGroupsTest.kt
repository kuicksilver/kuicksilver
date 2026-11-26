// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.http3

import io.kuicksilver.config.RateLimit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** The grouped Http3Settings builder (ADR-0026): every option reaches the settings, and the derived ones are recorded. */
class Http3SettingsGroupsTest {
    @Test fun everyOptionReachesTheSettings() {
        val s =
            http3Settings {
                maxFieldSectionSize = 1_001
                maxHeaderBlockTime = 3.seconds
                enableConnectProtocol = true
                h3Datagram = true
                earlyData = Http3EarlyDataPolicy.Reject425()
                qpack {
                    maxTableCapacity = 2_002
                    blockedStreams = 3
                    encoderMaxTableCapacity = 4_004
                }
                webTransport {
                    enabled = true
                    maxSessions = 2
                    initialMaxStreamsBidi = 5
                    initialMaxStreamsUni = 6
                    initialMaxData = 7_007
                }
                expert {
                    grease = false
                    maxEarlyPriorityUpdates = 8
                    glitchProtection = false
                }
            }
        for (x in listOf(s, s.toBuilder().build())) {
            assertEquals(1_001L, x.maxFieldSectionSize)
            assertEquals(3.seconds, x.maxHeaderBlockTime)
            assertEquals(true, x.enableConnectProtocol)
            assertEquals(true, x.h3Datagram)
            assertTrue(x.earlyData is Http3EarlyDataPolicy.Reject425)
            assertEquals(2_002L, x.qpackMaxTableCapacity)
            assertEquals(3L, x.qpackBlockedStreams)
            assertEquals(4_004L, x.encoderMaxTableCapacity)
            assertEquals(true, x.webTransport)
            assertEquals(2, x.webTransportMaxSessions)
            assertEquals(5L, x.webTransportInitialMaxStreamsBidi)
            assertEquals(6L, x.webTransportInitialMaxStreamsUni)
            assertEquals(7_007L, x.webTransportInitialMaxData)
            assertEquals(false, x.grease)
            assertEquals(8, x.maxEarlyPriorityUpdates)
            assertEquals(false, x.glitchProtection)
        }
    }

    /** A layer above (the Ktor engines) refuses the options it derives: the builder records which were assigned. */
    @Test fun derivedOptionsAreRecordedWhenAssigned() {
        val b = Http3Settings.Builder()
        b.maxFieldSectionSize = 10
        b.qpack { enableDynamicTable() }
        assertEquals(emptySet(), b.assignedOptions())
        b.enableConnectProtocol = true
        b.h3Datagram = true
        b.earlyData = Http3EarlyDataPolicy.WaitForHandshake()
        b.webTransport { maxSessions = 2 }
        assertEquals(setOf("enableConnectProtocol", "h3Datagram", "earlyData", "webTransport"), b.assignedOptions())
        assertEquals(emptySet(), b.build().toBuilder().assignedOptions())
    }

    @Test fun negative_webTransportNeedsExtendedConnectAndDatagrams() {
        val e = assertFailsWith<IllegalArgumentException> { http3Settings { webTransport { enabled = true } } }
        assertEquals("webTransport { enabled } needs enableConnectProtocol and h3Datagram", e.message)
    }

    @Test fun udpProxyRatesAreRateLimits() {
        val c = UdpProxyConfig()
        assertEquals(RateLimit(50_000, 5_000), c.clientPackets)
        assertEquals(RateLimit(20_000, 2_000), c.packets)
    }
}
