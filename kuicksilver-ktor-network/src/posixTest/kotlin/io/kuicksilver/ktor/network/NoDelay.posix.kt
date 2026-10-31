// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import platform.posix.IPPROTO_TCP
import platform.posix.TCP_NODELAY
import platform.posix.getsockopt
import platform.posix.socklen_tVar
import kotlin.test.assertEquals

@OptIn(ExperimentalForeignApi::class)
internal actual fun noDelayOf(fd: Int): Boolean =
    memScoped {
        val value = alloc<IntVar>()
        val size = alloc<socklen_tVar>()
        size.value = sizeOf<IntVar>().convert()
        assertEquals(0, getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, value.ptr, size.ptr), "getsockopt(TCP_NODELAY)")
        value.value != 0 // Darwin reports the flag's mask, not 1
    }
