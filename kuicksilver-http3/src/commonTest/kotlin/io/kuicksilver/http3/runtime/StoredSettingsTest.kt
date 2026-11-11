// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** RFC 9114 section 7.2.4.2: which SETTINGS after an accepted 0-RTT are compatible with the stored ones. */
class StoredSettingsTest {
    private val stored =
        mapOf(
            SettingsId.QPACK_MAX_TABLE_CAPACITY to 4096L,
            SettingsId.QPACK_BLOCKED_STREAMS to 16L,
            SettingsId.MAX_FIELD_SECTION_SIZE to 65_536L,
            SettingsId.ENABLE_CONNECT_PROTOCOL to 1L,
            SettingsId.H3_DATAGRAM to 0L,
            0x1234L to 7L, // unknown to us: not compared
        )

    @Test fun sameOrMoreIsCompatible() {
        assertNull(StoredSettings.incompatibility(stored, stored))
        val more = stored + (SettingsId.QPACK_BLOCKED_STREAMS to 100L) + (SettingsId.H3_DATAGRAM to 1L) - 0x1234L
        assertNull(StoredSettings.incompatibility(stored, more))
        // a setting stored with its default may be omitted
        assertNull(StoredSettings.incompatibility(stored, stored - SettingsId.H3_DATAGRAM))
    }

    @Test fun negative_lowerChangedOrOmittedIsIncompatible() {
        for (now in listOf(
            stored + (SettingsId.MAX_FIELD_SECTION_SIZE to 1_000L),
            stored + (SettingsId.QPACK_BLOCKED_STREAMS to 1L),
            stored + (SettingsId.ENABLE_CONNECT_PROTOCOL to 0L),
            stored + (SettingsId.QPACK_MAX_TABLE_CAPACITY to 8192L), // RFC 9204 section 3.2.3: the same non-zero value
            stored - SettingsId.MAX_FIELD_SECTION_SIZE,
            stored - SettingsId.ENABLE_CONNECT_PROTOCOL,
        )) {
            assertNotNull(StoredSettings.incompatibility(stored, now), "$now")
        }
    }

    @Test fun reservedIdentifiersAreNotStored() {
        val grease = FrameType.grease(3)
        assertEquals(listOf(SettingsId.H3_DATAGRAM to 1L), StoredSettings.kept(mapOf(grease to 9L, SettingsId.H3_DATAGRAM to 1L)))
    }
}
