// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

internal actual fun envVar(name: String): String? = System.getenv(name)

internal actual fun exitWith(code: Int): Nothing = kotlin.system.exitProcess(code)
