// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.contract

internal actual val contractPlatform: String = "jvm"

internal actual val contractOnWindows: Boolean = System.getProperty("os.name").orEmpty().startsWith("Windows")
