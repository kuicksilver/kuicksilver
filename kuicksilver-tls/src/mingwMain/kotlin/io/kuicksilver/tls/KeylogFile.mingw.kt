// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.ExperimentalForeignApi
import platform.posix.O_APPEND
import platform.posix.O_CREAT
import platform.posix.O_WRONLY
import platform.posix.open

/**
 * Windows: the CRT has no `O_NOFOLLOW`, no owner and no mode bits to check, so the file is only created; a junction or a
 * symlink at the path is followed. Keep the key log in a directory only this user can write (docs/guide/tls.md, Key logging).
 */
internal actual fun openKeylogFd(path: String): Int = open(path, O_WRONLY or O_CREAT or O_APPEND, 0x180 /* _S_IREAD | _S_IWRITE */)
