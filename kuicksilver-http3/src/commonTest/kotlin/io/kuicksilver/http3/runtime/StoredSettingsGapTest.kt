// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.webtransport.WtSettings
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The WebTransport settings among the stored 0-RTT settings (RFC 9114 section 7.2.4.2). */
class StoredSettingsGapTest {
    /**
     * draft-ietf-webtrans-http3-16 section 3.2 (0-RTT): "If the server accepts 0-RTT, the server MUST NOT reduce these
     * initial flow control values from those negotiated during the previous session. A client MUST close the connection
     * with H3_SETTINGS_ERROR if the SETTINGS frame received in the resumed connection reduces any flow control values from
     * the cached previous values." Against a server that does not speak draft-17, every WebTransport setting we understand
     * but draft-17's own is compared, the initial limits included.
     */
    @Test fun negative_loweredWebTransportSettingIsIncompatible() {
        assertTrue(SettingsId.WT_INITIAL_MAX_DATA in WtSettings.ALL)
        for (id in WtSettings.ALL - SettingsId.WT_ENABLED_DRAFT17) {
            val stored = mapOf(id to 1L)
            assertNull(StoredSettings.incompatibility(stored, stored), "0x${id.toString(16)} unchanged")
            assertNotNull(StoredSettings.incompatibility(stored, mapOf(id to 0L)), "0x${id.toString(16)} lowered")
            assertNotNull(StoredSettings.incompatibility(stored, emptyMap()), "0x${id.toString(16)} omitted")
        }
        val limits = mapOf(SettingsId.WT_INITIAL_MAX_DATA to 65_536L, SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to 10L)
        assertNotNull(StoredSettings.incompatibility(limits, limits + (SettingsId.WT_INITIAL_MAX_DATA to 65_535L)))
        assertNotNull(StoredSettings.incompatibility(limits, limits + (SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to 9L)))
        assertNull(StoredSettings.incompatibility(limits, limits + (SettingsId.WT_INITIAL_MAX_DATA to 1_000_000L)))
    }

    /**
     * draft-ietf-webtrans-http3-17 section 3.2: "a client MUST discard any values for the settings defined in this document
     * (Section 9.2) that it retained from a previous connection ... the requirements in Section 7.2.4.2 of [HTTP3] to treat
     * incompatible or omitted settings as a connection error do not apply to these settings". A server that still speaks
     * draft-17 may lower or omit the initial limits; draft-17's own setting is never compared (a server that now speaks
     * only draft-16 is held to the limits by draft-16, and to draft-16's setting).
     */
    @Test fun draft17SettingsAreTakenAsTheResumedServerSendsThem() {
        val d17 = SettingsId.WT_ENABLED_DRAFT17 to 1L
        val d16 = SettingsId.WT_ENABLED_DRAFT16 to 1L
        val limits =
            mapOf(
                SettingsId.WT_INITIAL_MAX_DATA to 65_536L,
                SettingsId.WT_INITIAL_MAX_STREAMS_BIDI to 10L,
                SettingsId.WT_INITIAL_MAX_STREAMS_UNI to 10L,
            )
        val stored = limits + d17 + d16
        assertNull(StoredSettings.incompatibility(stored, mapOf(d17, d16)), "limits omitted by a draft-17 server")
        assertNull(StoredSettings.incompatibility(stored, limits.mapValues { 1L } + d17 + d16), "limits lowered by a draft-17 server")
        assertNull(StoredSettings.incompatibility(stored, limits + d16), "draft-17 no longer announced")
        assertNotNull(StoredSettings.incompatibility(stored, limits.mapValues { 1L } + d16), "limits lowered by a draft-16 server")
        assertNotNull(StoredSettings.incompatibility(stored, limits + d17), "draft-16 no longer announced")
    }
}
