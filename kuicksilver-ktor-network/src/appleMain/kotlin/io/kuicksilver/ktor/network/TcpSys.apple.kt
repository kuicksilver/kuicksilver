// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.errors.PosixException
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.value
import platform.posix.SOL_SOCKET
import platform.posix.SO_NOSIGPIPE
import platform.posix.errno
import platform.posix.setsockopt

internal actual val bsdSockaddr: Boolean = true

internal actual val tcpSendFlags: Int = 0

internal actual fun tcpNoSigpipe(fd: Int) {
    memScoped {
        val one = alloc<IntVar>()
        one.value = 1
        if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, one.ptr, sizeOf<IntVar>().convert()) != 0) {
            throw PosixException.forErrno(errno, "setsockopt(SO_NOSIGPIPE)")
        }
    }
}
