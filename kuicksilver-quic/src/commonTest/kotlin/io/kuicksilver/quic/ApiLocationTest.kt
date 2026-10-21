// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlin.test.Test
import kotlin.test.assertEquals

/** Configuration types live in the root package; the deprecated `wire` aliases were removed before 0.2.0. */
class ApiLocationTest {
    @Test fun versionProfileLivesInTheRootPackage() {
        val v1: io.kuicksilver.quic.VersionProfile = io.kuicksilver.quic.VersionProfile.V1
        assertEquals(1, v1.version)
    }
}
