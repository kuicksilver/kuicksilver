// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.errors.PosixException
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toCPointer
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.io.IOException
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.AF_UNSPEC
import platform.posix.FIONBIO
import platform.posix.INVALID_SOCKET
import platform.posix.IPPROTO_TCP
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_ERROR
import platform.posix.SO_EXCLUSIVEADDRUSE
import platform.posix.WSADATA
import platform.posix.WSAECONNRESET
import platform.posix.WSAEINPROGRESS
import platform.posix.WSAEINTR
import platform.posix.WSAEWOULDBLOCK
import platform.posix.WSAGetLastError
import platform.posix.WSASocketW
import platform.posix.WSAStartup
import platform.posix.accept
import platform.posix.bind
import platform.posix.closesocket
import platform.posix.connect
import platform.posix.getpeername
import platform.posix.getsockname
import platform.posix.getsockopt
import platform.posix.ioctlsocket
import platform.posix.listen
import platform.posix.recv
import platform.posix.send
import platform.posix.setsockopt
import platform.posix.shutdown
import platform.windows.AI_NUMERICSERV
import platform.windows.GetHandleInformation
import platform.windows.HANDLE_FLAG_INHERIT
import platform.windows.SetHandleInformation
import platform.windows.addrinfo
import platform.windows.freeaddrinfo
import platform.windows.getaddrinfo

internal actual val afInet: Int = AF_INET
internal actual val afInet6: Int = AF_INET6
internal actual val bsdSockaddr: Boolean = false

private val winsock: Int by lazy {
    memScoped {
        val data = alloc<WSADATA>()
        WSAStartup(0x0202u, data.ptr)
    }
}

internal actual fun tcpStartup() {
    val rc = winsock
    if (rc != 0) throw PosixException.forErrno(rc, "WSAStartup")
}

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
        if (rc != 0) throw IOException("Failed to resolve address for $host: getaddrinfo error $rc")
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

private fun nonBlocking(fd: Int): Int =
    memScoped {
        val on = alloc<UIntVar>()
        on.value = 1u
        ioctlsocket(fd.convert(), FIONBIO.convert(), on.ptr)
    }

/** WSASocketW flag (winsock2.h; not in the platform klib): the handle is not inherited by child processes. */
private const val WSA_FLAG_NO_HANDLE_INHERIT: UInt = 0x80u

/**
 * Children started with handle inheritance (CreateProcess with bInheritHandles) must not get our sockets: an inherited
 * listener keeps the port bound after we close it, an inherited connection keeps the peer's connection open (Go and msquic
 * create every socket with WSA_FLAG_NO_HANDLE_INHERIT). Accepted sockets are cleared explicitly as well.
 */
private fun noInherit(s: ULong) {
    SetHandleInformation(s.toLong().toCPointer<CPointed>(), HANDLE_FLAG_INHERIT.convert(), 0u)
}

/** Test hook: whether [fd]'s handle would be inherited by a child process. */
internal fun tcpInheritableForTest(fd: Int): Boolean =
    memScoped {
        val flags = alloc<UIntVar>()
        check(GetHandleInformation(fd.toLong().toCPointer<CPointed>(), flags.ptr) != 0) { "GetHandleInformation" }
        flags.value and HANDLE_FLAG_INHERIT.convert<UInt>() != 0u
    }

internal actual fun tcpOpen(family: Int): Int {
    val s = WSASocketW(family, SOCK_STREAM, IPPROTO_TCP.convert(), null, 0u, WSA_FLAG_NO_HANDLE_INHERIT)
    if (s == INVALID_SOCKET) throw PosixException.forErrno(WSAGetLastError(), "socket")
    val fd = s.toInt()
    if (nonBlocking(fd) != 0) {
        val e = WSAGetLastError()
        closesocket(s)
        throw PosixException.forErrno(e, "ioctlsocket")
    }
    return fd
}

internal actual fun tcpConnect(
    fd: Int,
    to: TcpAddress,
): Boolean {
    val rc = to.bytes.usePinned { connect(fd.convert(), it.addressOf(0).reinterpret(), to.bytes.size) }
    if (rc == 0) return true
    val e = WSAGetLastError()
    if (tcpWouldBlock(e)) return false
    throw PosixException.forErrno(e, "connect")
}

internal actual fun tcpPendingError(fd: Int): Int =
    memScoped {
        val value = alloc<IntVar>()
        val size = alloc<IntVar>()
        size.value = sizeOf<IntVar>().toInt()
        if (getsockopt(fd.convert(), SOL_SOCKET, SO_ERROR, value.ptr.reinterpret(), size.ptr) != 0) {
            throw PosixException.forErrno(WSAGetLastError(), "getsockopt")
        }
        value.value
    }

internal actual fun tcpWouldBlock(error: Int): Boolean = error == WSAEWOULDBLOCK || error == WSAEINPROGRESS

internal actual fun tcpBindListen(
    fd: Int,
    to: TcpAddress,
    backlog: Int,
) {
    // nobody else binds this port while we listen, SO_REUSEADDR or not: without it another process could take over the
    // connections to it (Windows lets a SO_REUSEADDR socket bind a port in use; msquic and the UDP sockets here do the same)
    val exclusive =
        memScoped {
            val one = alloc<IntVar>()
            one.value = 1
            setsockopt(fd.convert(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, one.ptr.reinterpret(), sizeOf<IntVar>().toInt())
        }
    if (exclusive != 0) throw PosixException.forErrno(WSAGetLastError(), "setsockopt(SO_EXCLUSIVEADDRUSE)")
    if (to.bytes.usePinned { bind(fd.convert(), it.addressOf(0).reinterpret(), to.bytes.size) } != 0) {
        throw PosixException.forErrno(WSAGetLastError(), "bind")
    }
    if (listen(fd.convert(), backlog) != 0) throw PosixException.forErrno(WSAGetLastError(), "listen")
}

internal actual fun tcpAccept(
    fd: Int,
    peer: ByteArray,
): Int? {
    val client =
        memScoped {
            val size = alloc<IntVar>()
            size.value = peer.size
            peer.usePinned { accept(fd.convert(), it.addressOf(0).reinterpret(), size.ptr) }
        }
    if (client == INVALID_SOCKET) {
        val e = WSAGetLastError()
        // a connection reset before it was accepted is not the listener's failure
        if (tcpWouldBlock(e) || e == WSAEINTR || e == WSAECONNRESET) return null
        throw PosixException.forErrno(e, "accept")
    }
    noInherit(client.convert())
    val c = client.toInt()
    if (nonBlocking(c) != 0) {
        val e = WSAGetLastError()
        closesocket(client)
        throw PosixException.forErrno(e, "ioctlsocket")
    }
    return c
}

internal actual fun tcpRecv(
    fd: Int,
    buffer: ByteArray,
): Int {
    val n = buffer.usePinned { recv(fd.convert(), it.addressOf(0), buffer.size, 0) }
    if (n >= 0) return n
    val e = WSAGetLastError()
    if (tcpWouldBlock(e) || e == WSAEINTR) return -1
    throw PosixException.forErrno(e, "recv")
}

internal actual fun tcpSend(
    fd: Int,
    buffer: ByteArray,
    offset: Int,
    length: Int,
): Int {
    val n = buffer.usePinned { send(fd.convert(), it.addressOf(offset), length, 0) }
    if (n >= 0) return n
    val e = WSAGetLastError()
    if (tcpWouldBlock(e) || e == WSAEINTR) return -1
    throw PosixException.forErrno(e, "send")
}

internal actual fun tcpAddressOf(
    fd: Int,
    peer: Boolean,
): TcpAddress {
    val storage = ByteArray(SOCKADDR_STORAGE)
    val rc =
        memScoped {
            val size = alloc<IntVar>()
            size.value = storage.size
            storage.usePinned {
                if (peer) {
                    getpeername(fd.convert(), it.addressOf(0).reinterpret(), size.ptr)
                } else {
                    getsockname(fd.convert(), it.addressOf(0).reinterpret(), size.ptr)
                }
            }
        }
    if (rc != 0) throw PosixException.forErrno(WSAGetLastError(), if (peer) "getpeername" else "getsockname")
    return TcpAddress(storage)
}

internal actual fun tcpShutdown(
    fd: Int,
    how: Int,
) {
    shutdown(fd.convert(), how)
}

internal actual fun tcpClose(fd: Int) {
    closesocket(fd.convert())
}
