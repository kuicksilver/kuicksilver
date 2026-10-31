// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import platform.windows.getsockopt
import kotlin.test.assertEquals

@OptIn(ExperimentalForeignApi::class)
internal actual fun noDelayOf(fd: Int): Boolean =
    memScoped {
        val value = alloc<IntVar>()
        val size = alloc<IntVar>()
        size.value = sizeOf<IntVar>().toInt()
        // IPPROTO_TCP 6, TCP_NODELAY 1 (ws2def.h, ws2ipdef.h)
        assertEquals(0, getsockopt(fd.convert(), 6, 1, value.ptr.reinterpret(), size.ptr), "getsockopt(TCP_NODELAY)")
        value.value != 0
    }
