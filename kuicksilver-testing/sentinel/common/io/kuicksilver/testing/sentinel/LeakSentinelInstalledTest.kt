// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing.sentinel

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.LeakRegistry
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Copied with the sentinel into every module's tests, so it runs on every target the module's tests run on: the build
 * wired the sentinel there (the JUnit extension, the native entry point, the device runner builder), or this fails. A
 * wiring that breaks (an autodetection flag dropped, an entry point no longer passed) fails loudly, not silently.
 */
class LeakSentinelInstalledTest {
    @OptIn(InternalKuicksilverApi::class)
    @Test
    fun theSentinelIsInstalled() = assertTrue(LeakRegistry.enabled, "the leak sentinel is not installed in this test run")
}
