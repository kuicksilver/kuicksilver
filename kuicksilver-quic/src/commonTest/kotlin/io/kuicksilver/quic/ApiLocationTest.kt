// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/** K6 D1: configuration types live in the root package; the `wire` names stay as deprecated aliases for one release. */
class ApiLocationTest {
    @Test fun versionProfileLivesInTheRootPackage() {
        val v1: io.kuicksilver.quic.VersionProfile = io.kuicksilver.quic.VersionProfile.V1
        assertEquals(1, v1.version)
        @Suppress("DEPRECATION")
        assertSame<Any>(v1, io.kuicksilver.quic.wire.VersionProfile.V1)
    }
}
