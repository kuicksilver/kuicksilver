// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.cinterop.ExperimentalForeignApi
import platform.posix.F_GETFD
import platform.posix.fcntl

@OptIn(ExperimentalForeignApi::class)
internal actual fun openHandleCount(): Int = (0 until 4096).count { fcntl(it, F_GETFD) != -1 }
