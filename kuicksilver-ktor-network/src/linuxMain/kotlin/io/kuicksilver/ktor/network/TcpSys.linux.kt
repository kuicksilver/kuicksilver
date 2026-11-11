// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import platform.linux.SYS_accept4
import platform.posix.MSG_NOSIGNAL
import platform.posix.SOCK_CLOEXEC
import platform.posix.SOCK_NONBLOCK
import platform.posix.sockaddr
import platform.posix.socklen_tVar
import platform.posix.syscall

internal actual val bsdSockaddr: Boolean = false

internal actual val tcpSendFlags: Int = MSG_NOSIGNAL

internal actual fun tcpNoSigpipe(fd: Int) {}

internal actual val tcpAtomicFlags: Int = SOCK_NONBLOCK or SOCK_CLOEXEC

internal actual fun tcpAcceptFd(
    fd: Int,
    addr: CPointer<sockaddr>?,
    len: CPointer<socklen_tVar>?,
): Int = syscall(SYS_accept4.toLong(), fd, addr, len, tcpAtomicFlags).toInt() // glibc's accept4 is not in the platform klib
