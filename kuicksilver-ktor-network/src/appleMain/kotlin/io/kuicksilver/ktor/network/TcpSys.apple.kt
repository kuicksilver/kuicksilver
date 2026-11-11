// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.errors.PosixException
import kotlinx.cinterop.CPointer
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
import platform.posix.accept
import platform.posix.errno
import platform.posix.setsockopt
import platform.posix.sockaddr
import platform.posix.socklen_tVar

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

internal actual val tcpAtomicFlags: Int = 0 // no SOCK_CLOEXEC nor accept4 on Darwin: fcntl right after the call

internal actual fun tcpAcceptFd(
    fd: Int,
    addr: CPointer<sockaddr>?,
    len: CPointer<socklen_tVar>?,
): Int = accept(fd, addr, len)
