// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.kuicksilver.http3.http3Settings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

/** The engine bounds HTTP/3's `maxHeaderBlockTime` by `requestHeaderTimeout`, as it does HTTP/2's. */
class Http3HeaderDeadlineTest {
    @Test fun negative_aLongerFieldSectionDeadlineIsCutToTheRequestHeadDeadline() {
        val s =
            http3Settings {
                maxHeaderBlockTime = 60.seconds
                maxFieldSectionSize = 1000
            }
        val bounded = h3SettingsWithin(s, 30.seconds)
        assertEquals(30.seconds, bounded.maxHeaderBlockTime)
        assertEquals(1000, bounded.maxFieldSectionSize, "the other settings are kept")
    }

    @Test fun aShorterDeadlineIsKept() {
        val s = http3Settings { maxHeaderBlockTime = 5.seconds }
        assertSame(s, h3SettingsWithin(s, 30.seconds))
    }
}
