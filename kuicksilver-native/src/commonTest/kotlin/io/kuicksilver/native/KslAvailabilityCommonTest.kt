// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.native

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlin.test.Test
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** On every platform with a build, the library is available and the check agrees with [KslLoader.ensureLoaded]. */
class KslAvailabilityCommonTest {
    @Test fun availableOnABuiltPlatform() {
        assertSame(NativeAvailability.Available, KslLoader.availability())
        assertTrue(KslLoader.isAvailable())
        KslLoader.ensureLoaded()
        assertSame(KslLoader.availability(), KslLoader.availability())
    }
}
