// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.CPointer
import platform.posix.FD_CLOEXEC
import platform.posix.FILE
import platform.posix.F_GETFD
import platform.posix.fcntl
import platform.posix.fileno

internal actual fun closeOnExecOf(f: CPointer<FILE>): Boolean? = (fcntl(fileno(f), F_GETFD) and FD_CLOEXEC) != 0
