// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.CPointer
import platform.posix.FILE
import platform.posix.O_CLOEXEC
import platform.posix.O_RDONLY
import platform.posix.close
import platform.posix.fdopen
import platform.posix.open

/** `open(O_RDONLY | O_CLOEXEC)` and `fdopen`: the descriptor is close-on-exec from the start (no window before `fcntl`). */
internal actual fun openSecretFile(path: String): CPointer<FILE>? {
    val fd = open(path, O_RDONLY or O_CLOEXEC)
    if (fd < 0) return null
    return fdopen(fd, "rb") ?: run {
        close(fd)
        null
    }
}
