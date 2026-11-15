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
     * draft-ietf-webtrans-http3-16 section 4.5 (0-RTT): "If the server accepts 0-RTT, the server MUST NOT reduce these
     * initial flow control values from those negotiated during the previous session. A client MUST close the connection
     * with H3_SETTINGS_ERROR if the SETTINGS frame received in the resumed connection reduces any flow control values from
     * the cached previous values." Every WebTransport setting we understand is compared, the initial limits included.
     */
    @Test fun negative_loweredWebTransportSettingIsIncompatible() {
        assertTrue(SettingsId.WT_INITIAL_MAX_DATA in WtSettings.ALL)
        for (id in WtSettings.ALL) {
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
}
