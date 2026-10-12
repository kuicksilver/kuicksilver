// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import platform.posix.O_APPEND
import platform.posix.O_CLOEXEC
import platform.posix.O_CREAT
import platform.posix.O_NOFOLLOW
import platform.posix.O_WRONLY
import platform.posix.S_IFMT
import platform.posix.S_IFREG
import platform.posix.close
import platform.posix.fchmod
import platform.posix.fstat
import platform.posix.geteuid
import platform.posix.open
import platform.posix.stat

/** POSIX: `O_NOFOLLOW`, then `fstat` on the descriptor itself (no window for a swap): regular, one hard link, owned by the effective user, tightened to 0600. */
internal actual fun openKeylogFd(path: String): Int {
    val fd = open(path, O_WRONLY or O_CREAT or O_APPEND or O_NOFOLLOW or O_CLOEXEC, 0x180 /* 0600 */)
    if (fd < 0) return -1
    val ok =
        memScoped {
            val st = alloc<stat>()
            if (fstat(fd, st.ptr) != 0) return@memScoped false
            val mode: Int = st.st_mode.convert()
            if (mode and S_IFMT != S_IFREG) return@memScoped false
            if (st.st_uid != geteuid()) return@memScoped false
            if (fdLinkCount(fd) != 1L) return@memScoped false // another name may sit where others can read it
            if (mode and 0x3F /* 077 */ != 0 && fchmod(fd, 0x180.convert()) != 0) return@memScoped false
            true
        }
    if (!ok) {
        close(fd)
        return -1
    }
    return fd
}

/**
 * The hard-link count of an open file, or -1 if `fstat` fails. `st_nlink` is 64 bits on linuxX64 and 32 on linuxArm64,
 * which shared Linux code may not touch, so each architecture reads it in its own source set.
 */
internal expect fun fdLinkCount(fd: Int): Long
