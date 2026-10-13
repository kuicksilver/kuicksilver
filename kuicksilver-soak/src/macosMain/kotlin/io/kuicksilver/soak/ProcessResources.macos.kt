// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.soak

import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import platform.darwin.KERN_SUCCESS
import platform.darwin.MACH_TASK_BASIC_INFO
import platform.darwin.mach_msg_type_number_tVar
import platform.darwin.mach_task_basic_info
import platform.darwin.mach_task_self_
import platform.darwin.natural_tVar
import platform.darwin.task_info
import platform.posix.F_GETFD
import platform.posix.fcntl
import platform.posix.getdtablesize

/** `task_info(MACH_TASK_BASIC_INFO)`: the resident size of this task. */
internal actual fun rssKiB(): Long =
    memScoped {
        val info = alloc<mach_task_basic_info>()
        val count = alloc<mach_msg_type_number_tVar>()
        count.value = (sizeOf<mach_task_basic_info>() / sizeOf<natural_tVar>()).toUInt()
        if (task_info(mach_task_self_, MACH_TASK_BASIC_INFO.toUInt(), info.ptr.reinterpret(), count.ptr) != KERN_SUCCESS) return -1
        info.resident_size.toLong() / 1024
    }

/** Descriptors below the table size that answer F_GETFD (no /proc on macOS; capped at 65536 probes). */
internal actual fun openFds(): Long {
    var n = 0L
    for (fd in 0 until minOf(getdtablesize(), 65536)) if (fcntl(fd, F_GETFD) != -1) n++
    return n
}
