// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.CPointer
import platform.posix.FILE
import platform.posix.fopen

/** `N`: the Windows C runtime opens the handle not inheritable by child processes. */
internal actual fun openSecretFile(path: String): CPointer<FILE>? = fopen(path, "rbN")
