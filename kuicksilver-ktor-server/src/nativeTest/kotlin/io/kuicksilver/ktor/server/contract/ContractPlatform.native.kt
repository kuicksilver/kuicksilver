// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.contract

/** No annotation reflection here: the common suites pass `http1Only`/`http2Only` to `runTest` instead. */
internal actual fun EngineTestBase<*, *>.testMarkers(): Set<String> = emptySet()

/** kotlin.test has no assumptions: the skipped test passes without running. */
internal actual fun skipTest(reason: String) {}

internal actual val vendoredJvmContentSuite: Boolean = false

@OptIn(kotlin.experimental.ExperimentalNativeApi::class)
internal actual val reusePortFlowHashing: Boolean =
    kotlin.native.Platform.osFamily == kotlin.native.OsFamily.LINUX || kotlin.native.Platform.osFamily == kotlin.native.OsFamily.ANDROID
