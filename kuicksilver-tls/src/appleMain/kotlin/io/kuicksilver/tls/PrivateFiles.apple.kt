// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import platform.posix.EEXIST
import platform.posix.ELOOP
import platform.posix.O_CLOEXEC
import platform.posix.O_CREAT
import platform.posix.O_EXCL
import platform.posix.O_NOFOLLOW
import platform.posix.O_WRONLY
import platform.posix.S_IFDIR
import platform.posix.S_IFMT
import platform.posix.errno
import platform.posix.geteuid
import platform.posix.lstat
import platform.posix.mkdir
import platform.posix.open
import platform.posix.stat

/** POSIX: `lstat` (a symlink is not followed): a directory of the effective user, not writable by others unless sticky. */
internal actual fun privateDirectoryProblem(path: String): String? {
    if (mkdir(path, 0x1C0.convert() /* 0700 */) != 0 && errno != EEXIST) return "cannot be created (errno $errno)"
    return memScoped {
        val st = alloc<stat>()
        if (lstat(path, st.ptr) != 0) return@memScoped "cannot be read (errno $errno)"
        val mode: Int = st.st_mode.toInt()
        when {
            mode and S_IFMT != S_IFDIR -> "not a directory (or a symbolic link)"
            st.st_uid != geteuid() -> "owned by another user"
            mode and 0x12 /* 022 */ != 0 && mode and 0x200 /* 01000 */ == 0 -> "writable by group or others without the sticky bit"
            else -> null
        }
    }
}

/** POSIX: `O_CREAT | O_EXCL | O_NOFOLLOW`: any existing name fails (`EEXIST`, or `ELOOP` for a symlink on some systems). */
internal actual fun openExclusive(path: String): Int {
    val fd = open(path, O_WRONLY or O_CREAT or O_EXCL or O_NOFOLLOW or O_CLOEXEC, 0x180 /* 0600 */)
    if (fd >= 0) return fd
    return if (errno == EEXIST || errno == ELOOP) EXISTS else -1
}
