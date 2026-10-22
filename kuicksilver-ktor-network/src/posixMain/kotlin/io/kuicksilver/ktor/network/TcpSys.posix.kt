// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, UnsafeNumber::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.errors.PosixException
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.UnsafeNumber
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.plus
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.io.IOException
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.AF_UNSPEC
import platform.posix.AI_NUMERICSERV
import platform.posix.EAGAIN
import platform.posix.ECONNABORTED
import platform.posix.EINPROGRESS
import platform.posix.EINTR
import platform.posix.EWOULDBLOCK
import platform.posix.FD_CLOEXEC
import platform.posix.F_GETFL
import platform.posix.F_SETFD
import platform.posix.F_SETFL
import platform.posix.O_NONBLOCK
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_ERROR
import platform.posix.SO_LINGER
import platform.posix.accept
import platform.posix.addrinfo
import platform.posix.bind
import platform.posix.close
import platform.posix.connect
import platform.posix.errno
import platform.posix.fcntl
import platform.posix.freeaddrinfo
import platform.posix.gai_strerror
import platform.posix.getaddrinfo
import platform.posix.getpeername
import platform.posix.getsockname
import platform.posix.getsockopt
import platform.posix.linger
import platform.posix.listen
import platform.posix.recv
import platform.posix.send
import platform.posix.setsockopt
import platform.posix.shutdown
import platform.posix.socket
import platform.posix.socklen_tVar

internal actual val afInet: Int = AF_INET
internal actual val afInet6: Int = AF_INET6

internal actual fun tcpStartup() {}

internal actual fun tcpResolve(
    host: String,
    port: Int,
): List<TcpAddress> =
    memScoped {
        val hints = alloc<addrinfo>()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_NUMERICSERV
        val result = alloc<CPointerVar<addrinfo>>()
        val rc = getaddrinfo(host, port.toString(), hints.ptr, result.ptr)
        if (rc != 0) throw IOException("Failed to resolve address for $host: ${gai_strerror(rc)?.toKString()} ($rc)")
        try {
            val out = ArrayList<TcpAddress>()
            var ai = result.value
            while (ai != null) {
                val a = ai.pointed
                val sa = a.ai_addr
                if (sa != null && (a.ai_family == AF_INET || a.ai_family == AF_INET6)) {
                    out += TcpAddress(sa.reinterpret<ByteVar>().readBytes(a.ai_addrlen.convert()))
                }
                ai = a.ai_next
            }
            out
        } finally {
            freeaddrinfo(result.value)
        }
    }

internal actual fun tcpOpen(family: Int): Int {
    val fd = socket(family, SOCK_STREAM, 0)
    if (fd < 0) throw PosixException.forErrno(errno, "socket")
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) or O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        val e = errno
        close(fd)
        throw PosixException.forErrno(e, "fcntl")
    }
    try {
        tcpNoSigpipe(fd)
    } catch (e: Throwable) {
        close(fd)
        throw e
    }
    return fd
}

internal actual fun tcpConnect(
    fd: Int,
    to: TcpAddress,
): Boolean {
    val rc = to.bytes.usePinned { connect(fd, it.addressOf(0).reinterpret(), to.bytes.size.convert()) }
    if (rc == 0) return true
    val e = errno
    if (e == EINPROGRESS || e == EINTR) return false
    throw PosixException.forErrno(e, "connect")
}

internal actual fun tcpPendingError(fd: Int): Int =
    memScoped {
        val value = alloc<IntVar>()
        val size = alloc<socklen_tVar>()
        size.value = sizeOf<IntVar>().convert()
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, value.ptr, size.ptr) != 0) throw PosixException.forErrno(errno, "getsockopt")
        value.value
    }

internal actual fun tcpWouldBlock(error: Int): Boolean = error == EAGAIN || error == EWOULDBLOCK || error == EINPROGRESS

internal actual fun tcpBindListen(
    fd: Int,
    to: TcpAddress,
    backlog: Int,
) {
    if (to.bytes.usePinned { bind(fd, it.addressOf(0).reinterpret(), to.bytes.size.convert()) } != 0) {
        throw PosixException.forErrno(errno, "bind")
    }
    if (listen(fd, backlog) != 0) throw PosixException.forErrno(errno, "listen")
}

internal actual fun tcpAccept(
    fd: Int,
    peer: ByteArray,
): Int? {
    val client =
        memScoped {
            val size = alloc<socklen_tVar>()
            size.value = peer.size.convert()
            peer.usePinned { accept(fd, it.addressOf(0).reinterpret(), size.ptr) }
        }
    if (client < 0) {
        val e = errno
        // a connection reset before it was accepted is not the listener's failure
        if (tcpWouldBlock(e) || e == EINTR || e == ECONNABORTED) return null
        throw PosixException.forErrno(e, "accept")
    }
    if (fcntl(client, F_SETFL, fcntl(client, F_GETFL) or O_NONBLOCK) < 0 || fcntl(client, F_SETFD, FD_CLOEXEC) < 0) {
        val e = errno
        close(client)
        throw PosixException.forErrno(e, "fcntl")
    }
    try {
        tcpNoSigpipe(client)
    } catch (e: Throwable) {
        close(client)
        throw e
    }
    return client
}

internal actual fun tcpRecv(
    fd: Int,
    buffer: ByteArray,
): Int {
    val n = buffer.usePinned { recv(fd, it.addressOf(0), buffer.size.convert(), 0) }.toInt()
    if (n >= 0) return n
    val e = errno
    if (tcpWouldBlock(e) || e == EINTR) return -1
    throw PosixException.forErrno(e, "recv")
}

internal actual fun tcpSend(
    fd: Int,
    buffer: ByteArray,
    offset: Int,
    length: Int,
): Int {
    val n = buffer.usePinned { send(fd, it.addressOf(offset), length.convert(), tcpSendFlags) }.toInt()
    if (n >= 0) return n
    val e = errno
    if (tcpWouldBlock(e) || e == EINTR) return -1
    throw PosixException.forErrno(e, "send")
}

internal actual fun tcpAddressOf(
    fd: Int,
    peer: Boolean,
): TcpAddress {
    val storage = ByteArray(SOCKADDR_STORAGE)
    val rc =
        memScoped {
            val size = alloc<socklen_tVar>()
            size.value = storage.size.convert()
            storage.usePinned {
                if (peer) {
                    getpeername(
                        fd,
                        it.addressOf(0).reinterpret(),
                        size.ptr,
                    )
                } else {
                    getsockname(fd, it.addressOf(0).reinterpret(), size.ptr)
                }
            }
        }
    if (rc != 0) throw PosixException.forErrno(errno, if (peer) "getpeername" else "getsockname")
    return TcpAddress(storage)
}

internal actual fun tcpShutdown(
    fd: Int,
    how: Int,
) {
    shutdown(fd, how)
}

internal actual fun tcpLingerZero(fd: Int) {
    memScoped {
        val l = alloc<linger>()
        l.l_onoff = 1
        l.l_linger = 0
        if (setsockopt(fd, SOL_SOCKET, SO_LINGER, l.ptr, sizeOf<linger>().convert()) != 0) {
            throw PosixException.forErrno(errno, "setsockopt(SO_LINGER)")
        }
    }
}

internal actual fun tcpClose(fd: Int) {
    close(fd)
}

/** Keeps a write to a closed connection from raising SIGPIPE (SO_NOSIGPIPE on Apple; Linux passes MSG_NOSIGNAL to every send). */
internal expect fun tcpNoSigpipe(fd: Int)

/** The flags of every `send`: MSG_NOSIGNAL on Linux, 0 on Apple. */
internal expect val tcpSendFlags: Int
