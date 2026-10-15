// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.windows.DWORDVar
import platform.windows.GetCurrentProcess
import platform.windows.GetProcessHandleCount

@OptIn(ExperimentalForeignApi::class)
internal actual fun openHandleCount(): Int =
    memScoped {
        val count = alloc<DWORDVar>()
        check(GetProcessHandleCount(GetCurrentProcess(), count.ptr) != 0) { "GetProcessHandleCount failed" }
        count.value.toInt()
    }
