// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.tls

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import platform.posix.fstat
import platform.posix.stat

internal actual fun fdLinkCount(fd: Int): Long =
    memScoped {
        val st = alloc<stat>()
        if (fstat(fd, st.ptr) != 0) -1L else st.st_nlink.toLong()
    }
