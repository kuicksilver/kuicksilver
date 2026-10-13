// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.contract

internal actual val contractPlatform: String = "native"

@OptIn(kotlin.experimental.ExperimentalNativeApi::class)
internal actual val contractOnWindows: Boolean = Platform.osFamily == OsFamily.WINDOWS
