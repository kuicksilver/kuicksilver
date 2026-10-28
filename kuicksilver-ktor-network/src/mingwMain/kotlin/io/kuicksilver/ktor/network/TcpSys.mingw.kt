// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import io.ktor.utils.io.errors.PosixException
import io.kuicksilver.ktor.network.wsa.ksl_wsa_accept
import io.kuicksilver.ktor.network.wsa.ksl_wsa_address
import io.kuicksilver.ktor.network.wsa.ksl_wsa_bind
import io.kuicksilver.ktor.network.wsa.ksl_wsa_connect
import io.kuicksilver.ktor.network.wsa.ksl_wsa_listen
import io.kuicksilver.ktor.network.wsa.ksl_wsa_nonblocking
import io.kuicksilver.ktor.network.wsa.ksl_wsa_recv
import io.kuicksilver.ktor.network.wsa.ksl_wsa_send
import io.kuicksilver.ktor.network.wsa.ksl_wsa_setsockopt
import io.kuicksilver.ktor.network.wsa.ksl_wsa_so_error
import io.kuicksilver.ktor.network.wsa.ksl_wsa_socket
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointed
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.UShortVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toCPointer
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.io.IOException
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.AF_UNSPEC
import platform.posix.INVALID_SOCKET
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_EXCLUSIVEADDRUSE
import platform.posix.SO_LINGER
import platform.posix.WSADATA
import platform.posix.WSAECONNRESET
import platform.posix.WSAEINPROGRESS
import platform.posix.WSAEINTR
import platform.posix.WSAEWOULDBLOCK
import platform.posix.WSAStartup
import platform.posix.closesocket
import platform.posix.shutdown
import platform.windows.AI_NUMERICSERV
import platform.windows.GetHandleInformation
import platform.windows.HANDLE_FLAG_INHERIT
import platform.windows.SetHandleInformation
import platform.windows.addrinfo
import platform.windows.freeaddrinfo
import platform.windows.getaddrinfo
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

internal actual val afInet: Int = AF_INET
internal actual val afInet6: Int = AF_INET6
internal actual val bsdSockaddr: Boolean = false

// unread input stays buffered until the close, as on Linux: after SD_RECEIVE, Winsock resets the connection on more data
internal actual val tcpShutdownReadBeforeEnd: Boolean = false

// a lost FD_READ or FD_CLOSE delays the read by at most this, see tcpReadRecheck
internal actual val tcpReadRecheck: Duration? = 1.seconds

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

/** Makes [fd] non-blocking: 0, or the Winsock error (captured in C, see kslwsa.def). */
private fun nonBlocking(fd: Int): Int =
    memScoped {
        val err = alloc<IntVar>()
        ksl_wsa_nonblocking(fd.convert(), err.ptr)
        err.value
    }

/**
 * Children started with handle inheritance (CreateProcess with bInheritHandles) must not get our sockets: an inherited
 * listener keeps the port bound after we close it, an inherited connection keeps the peer's connection open (Go and msquic
 * create every socket with WSA_FLAG_NO_HANDLE_INHERIT, as ksl_wsa_socket does). Accepted sockets are cleared explicitly.
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

/*
 * Every Winsock call whose failure is told by the last error goes through the C shim of kslwsa.def, which reads
 * WSAGetLastError() in the same C function. Read from Kotlin, even at once inside the pinned block, it was already reset:
 * the return from a C call passes through the Kotlin/Native runtime (thread state switch, safepoint, a wait for the GC;
 * thread-locals are emulated on mingw), which can make Win32 calls of its own, so a pending connect read as error 0.
 */

internal actual fun tcpOpen(family: Int): Int {
    val (s, e) =
        memScoped {
            val err = alloc<IntVar>()
            ksl_wsa_socket(family, err.ptr) to err.value
        }
    if (s == INVALID_SOCKET) throw PosixException.forErrno(e, "socket")
    val fd = s.toInt()
    val nbError = nonBlocking(fd)
    if (nbError != 0) {
        closesocket(s)
        throw PosixException.forErrno(nbError, "ioctlsocket")
    }
    return fd
}

internal actual fun tcpConnect(
    fd: Int,
    to: TcpAddress,
): Boolean {
    val (rc, e) =
        memScoped {
            val err = alloc<IntVar>()
            to.bytes.usePinned { ksl_wsa_connect(fd.convert(), it.addressOf(0), to.bytes.size, err.ptr) } to err.value
        }
    if (rc == 0) return true
    if (tcpWouldBlock(e)) return false
    if (e == 0) {
        // Not expected since the error is captured in C, but a failed connect without an error must not fail a connect
        // that is only pending (the original symptom): it is taken as pending when the socket has no error of its own;
        // the selector then waits for it to become writable and reads SO_ERROR again. A real error fails it at once.
        val pending = tcpPendingError(fd)
        if (pending == 0) return false
        throw PosixException.forErrno(pending, "connect")
    }
    throw PosixException.forErrno(e, "connect")
}

internal actual fun tcpPendingError(fd: Int): Int {
    val (rc, value, e) =
        memScoped {
            val value = alloc<IntVar>()
            val err = alloc<IntVar>()
            Triple(ksl_wsa_so_error(fd.convert(), value.ptr, err.ptr), value.value, err.value)
        }
    if (rc != 0) throw PosixException.forErrno(e, "getsockopt")
    return value
}

internal actual fun tcpWouldBlock(error: Int): Boolean = error == WSAEWOULDBLOCK || error == WSAEINPROGRESS

internal actual fun tcpBindListen(
    fd: Int,
    to: TcpAddress,
    backlog: Int,
) {
    memScoped {
        val err = alloc<IntVar>()
        // nobody else binds this port while we listen, SO_REUSEADDR or not: without it another process could take over the
        // connections to it (Windows lets a SO_REUSEADDR socket bind a port in use; msquic and the UDP sockets here do the same)
        val one = alloc<IntVar>()
        one.value = 1
        if (ksl_wsa_setsockopt(fd.convert(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, one.ptr, sizeOf<IntVar>().toInt(), err.ptr) != 0) {
            throw PosixException.forErrno(err.value, "setsockopt(SO_EXCLUSIVEADDRUSE)")
        }
        val bound = to.bytes.usePinned { ksl_wsa_bind(fd.convert(), it.addressOf(0), to.bytes.size, err.ptr) }
        if (bound != 0) throw PosixException.forErrno(err.value, "bind")
        if (ksl_wsa_listen(fd.convert(), backlog, err.ptr) != 0) throw PosixException.forErrno(err.value, "listen")
    }
}

internal actual fun tcpAccept(
    fd: Int,
    peer: ByteArray,
): Int? {
    val (client, e) =
        memScoped {
            val size = alloc<IntVar>()
            size.value = peer.size
            val err = alloc<IntVar>()
            peer.usePinned { ksl_wsa_accept(fd.convert(), it.addressOf(0), size.ptr, err.ptr) } to err.value
        }
    if (client == INVALID_SOCKET) {
        // a connection reset before it was accepted is not the listener's failure
        if (tcpWouldBlock(e) || e == WSAEINTR || e == WSAECONNRESET) return null
        throw PosixException.forErrno(e, "accept")
    }
    noInherit(client)
    val c = client.toInt()
    val nbError = nonBlocking(c)
    if (nbError != 0) {
        closesocket(client)
        throw PosixException.forErrno(nbError, "ioctlsocket")
    }
    return c
}

internal actual fun tcpRecv(
    fd: Int,
    buffer: ByteArray,
): Int {
    val (n, e) =
        memScoped {
            val err = alloc<IntVar>()
            buffer.usePinned { ksl_wsa_recv(fd.convert(), it.addressOf(0), buffer.size, err.ptr) } to err.value
        }
    if (n >= 0) return n
    if (tcpWouldBlock(e) || e == WSAEINTR) return -1
    throw PosixException.forErrno(e, "recv")
}

internal actual fun tcpSend(
    fd: Int,
    buffer: ByteArray,
    offset: Int,
    length: Int,
): Int {
    val (n, e) =
        memScoped {
            val err = alloc<IntVar>()
            buffer.usePinned { ksl_wsa_send(fd.convert(), it.addressOf(offset), length, err.ptr) } to err.value
        }
    if (n >= 0) return n
    if (tcpWouldBlock(e) || e == WSAEINTR) return -1
    throw PosixException.forErrno(e, "send")
}

internal actual fun tcpAddressOf(
    fd: Int,
    peer: Boolean,
): TcpAddress {
    val storage = ByteArray(SOCKADDR_STORAGE)
    val (rc, e) =
        memScoped {
            val size = alloc<IntVar>()
            size.value = storage.size
            val err = alloc<IntVar>()
            storage.usePinned { ksl_wsa_address(fd.convert(), if (peer) 1 else 0, it.addressOf(0), size.ptr, err.ptr) } to err.value
        }
    if (rc != 0) throw PosixException.forErrno(e, if (peer) "getpeername" else "getsockname")
    return TcpAddress(storage)
}

internal actual fun tcpShutdown(
    fd: Int,
    how: Int,
) {
    shutdown(fd.convert(), how)
}

internal actual fun tcpLingerZero(fd: Int) {
    memScoped {
        // struct linger of Winsock: u_short l_onoff, u_short l_linger
        val l = allocArray<UShortVar>(2)
        l[0] = 1u
        l[1] = 0u
        val err = alloc<IntVar>()
        if (ksl_wsa_setsockopt(fd.convert(), SOL_SOCKET, SO_LINGER, l, 2 * sizeOf<UShortVar>().toInt(), err.ptr) != 0) {
            throw PosixException.forErrno(err.value, "setsockopt(SO_LINGER)")
        }
    }
}

internal actual fun tcpClose(fd: Int) {
    closesocket(fd.convert())
}
