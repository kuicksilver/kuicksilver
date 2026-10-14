// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.interop

import kotlinx.cinterop.toKString
import platform.posix.getenv

internal actual fun envVar(name: String): String? = getenv(name)?.toKString()

internal actual fun exitWith(code: Int): Nothing = kotlin.system.exitProcess(code)
