// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.ExperimentalForeignApi
import platform.posix.EEXIST
import platform.posix.O_BINARY
import platform.posix.O_CREAT
import platform.posix.O_EXCL
import platform.posix.O_WRONLY
import platform.posix.errno
import platform.posix.mkdir
import platform.posix.open
import platform.windows.FILE_ATTRIBUTE_DIRECTORY
import platform.windows.FILE_ATTRIBUTE_REPARSE_POINT
import platform.windows.GetFileAttributesW
import platform.windows.INVALID_FILE_ATTRIBUTES

/**
 * Windows: no owner or mode bits through the CRT; the directory must exist as a directory and not be a reparse point (a
 * junction or symlink, which would redirect the files). Keep it under the user's profile.
 */
internal actual fun privateDirectoryProblem(path: String): String? {
    if (mkdir(path) != 0 && errno != EEXIST) return "cannot be created (errno $errno)"
    val a = GetFileAttributesW(path)
    return when {
        a == INVALID_FILE_ATTRIBUTES -> "cannot be read"
        a and FILE_ATTRIBUTE_DIRECTORY.toUInt() == 0u -> "not a directory"
        a and FILE_ATTRIBUTE_REPARSE_POINT.toUInt() != 0u -> "a junction or symbolic link"
        else -> null
    }
}

/** Windows: `O_CREAT | O_EXCL` is `CREATE_NEW`, which fails on any existing name (a symlink or junction included). */
internal actual fun openExclusive(path: String): Int {
    val fd = open(path, O_WRONLY or O_CREAT or O_EXCL or O_BINARY, 0x180 /* _S_IREAD | _S_IWRITE */)
    if (fd >= 0) return fd
    return if (errno == EEXIST) EXISTS else -1
}
