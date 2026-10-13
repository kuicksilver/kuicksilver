// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import platform.posix.O_APPEND
import platform.posix.O_CREAT
import platform.posix.O_WRONLY
import platform.posix.S_IFMT
import platform.posix.S_IFREG
import platform.posix.close
import platform.posix.fstat
import platform.posix.open
import platform.posix.stat

/**
 * Windows: the CRT has no `O_NOFOLLOW`, no owner and no mode bits to check, so the file is only created; a junction or a
 * symlink at the path is followed; anything but a regular file (a device, a pipe) is refused. Keep the key log in a
 * directory only this user can write (docs/guide/tls.md, Key logging).
 */
internal actual fun openKeylogFd(path: String): Int {
    val fd = open(path, O_WRONLY or O_CREAT or O_APPEND, 0x180 /* _S_IREAD | _S_IWRITE */)
    if (fd < 0) return -1
    // only a regular file: not a device (NUL, CON) or a pipe
    val regular =
        memScoped {
            val st = alloc<stat>()
            fstat(fd, st.ptr) == 0 && st.st_mode.toInt() and S_IFMT == S_IFREG
        }
    if (!regular) {
        close(fd)
        return -1
    }
    return fd
}
