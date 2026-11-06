// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.bench

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

/** `task_info(MACH_TASK_BASIC_INFO)`: the resident size of this task. */
internal actual fun residentBytes(): Long =
    memScoped {
        val info = alloc<mach_task_basic_info>()
        val count = alloc<mach_msg_type_number_tVar>()
        count.value = (sizeOf<mach_task_basic_info>() / sizeOf<natural_tVar>()).toUInt()
        if (task_info(mach_task_self_, MACH_TASK_BASIC_INFO.toUInt(), info.ptr.reinterpret(), count.ptr) != KERN_SUCCESS) return -1
        info.resident_size.toLong()
    }

/** `malloc_zone_statistics` over every zone: bytes in use. */
internal actual fun cHeapInUseBytes(): Long = io.kuicksilver.bench.mallocstats.ksl_bench_malloc_in_use().toLong()
