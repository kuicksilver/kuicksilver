// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.CPointer
import platform.posix.FILE

/** The Windows C runtime has no close-on-exec flag to read back ("N" is checked by the C runtime only). */
internal actual fun closeOnExecOf(f: CPointer<FILE>): Boolean? = null
