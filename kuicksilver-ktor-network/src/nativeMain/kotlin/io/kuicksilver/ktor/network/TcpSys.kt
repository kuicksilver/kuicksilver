// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.sockets.InetSocketAddress

/*
 * The system calls of the native TCP sockets (TcpSockets.native.kt): POSIX on Linux and Apple, Winsock on Windows. Every
 * function takes the descriptor as an Int, as ktor-network's selector does. Failures throw ktor's PosixException with the
 * system's error code (errno, or WSAGetLastError on Windows); "would block" is a return value, never an exception.
 */

/** `AF_INET` of this platform. */
internal expect val afInet: Int

/** `AF_INET6` of this platform. */
internal expect val afInet6: Int

/** Whether a `sockaddr` starts with a length byte and a one-byte family (BSD, Apple), not a two-byte family (Linux, Windows). */
internal expect val bsdSockaddr: Boolean

/** Starts the socket library once (Winsock); nothing elsewhere. */
internal expect fun tcpStartup()

/**
 * The `sockaddr`s `getaddrinfo` gives for [host] (an address literal or a name) and [port], stream sockets, in its order;
 * with [numericHost], `AI_NUMERICHOST`: [host] is a literal and is never looked up.
 */
internal expect fun tcpResolve(
    host: String,
    port: Int,
    numericHost: Boolean = false,
): List<Sockaddr>

/** A non-blocking stream socket of [family] (close-on-exec, no SIGPIPE). */
internal expect fun tcpOpen(family: Int): Int

/** Starts connecting [fd] to [to]: true when connected at once, false while the connect is in progress. */
internal expect fun tcpConnect(
    fd: Int,
    to: Sockaddr,
): Boolean

/** `SO_ERROR` of [fd]: 0 once a pending connect has succeeded. */
internal expect fun tcpPendingError(fd: Int): Int

/** Whether [error] means "not yet" (EAGAIN, EWOULDBLOCK, EINPROGRESS; their WSA twins). */
internal expect fun tcpWouldBlock(error: Int): Boolean

/** Binds [fd] to [to] and listens with [backlog]. */
internal expect fun tcpBindListen(
    fd: Int,
    to: Sockaddr,
    backlog: Int,
)

/** Accepts a connection of the listening [fd] as a non-blocking socket with its peer's address in [peer]; null while none is pending. */
internal expect fun tcpAccept(
    fd: Int,
    peer: ByteArray,
): Int?

/** Receives into [buffer]: the byte count, 0 at the end of the stream, -1 while nothing is available. */
internal expect fun tcpRecv(
    fd: Int,
    buffer: ByteArray,
): Int

/** Sends [length] bytes of [buffer] from [offset]: the count sent, -1 while the send buffer is full. */
internal expect fun tcpSend(
    fd: Int,
    buffer: ByteArray,
    offset: Int,
    length: Int,
): Int

/** The local (`getsockname`) or, with [peer], the remote (`getpeername`) address of [fd]. */
internal expect fun tcpAddressOf(
    fd: Int,
    peer: Boolean,
): Sockaddr

/** `shutdown` of the receiving ([TCP_SHUT_RD]), sending ([TCP_SHUT_WR]) or both ([TCP_SHUT_RDWR]) directions; errors ignored. */
internal expect fun tcpShutdown(
    fd: Int,
    how: Int,
)

/** `SO_LINGER` on with a zero timeout: closing [fd] then sends a reset and drops what is unsent. */
internal expect fun tcpLingerZero(fd: Int)

/** Closes [fd] that never reached the selector (which otherwise closes it). */
internal expect fun tcpClose(fd: Int)

// SHUT_RD / SD_RECEIVE, SHUT_WR / SD_SEND, SHUT_RDWR / SD_BOTH: the same values on every platform
internal const val TCP_SHUT_RD = 0
internal const val TCP_SHUT_WR = 1
internal const val TCP_SHUT_RDWR = 2

/** The size of a `sockaddr_storage`, enough for any address family. */
internal const val SOCKADDR_STORAGE = 128

/**
 * A `sockaddr_in` or `sockaddr_in6` as bytes. Both layouts put the port (network order) at offset 2, the IPv4 address at 4
 * and the IPv6 address at 8 (its scope id at 24); the family is a byte at offset 1 (BSD, after the length byte) or a
 * little-endian 16-bit value at 0 (Linux and Windows; every Kotlin/Native target of this library is little-endian).
 */
internal class Sockaddr(
    val bytes: ByteArray,
) {
    val family: Int get() = if (bsdSockaddr) bytes[1].u() else bytes[0].u() or (bytes[1].u() shl 8)
    val port: Int get() = (bytes[2].u() shl 8) or bytes[3].u()
    val ip: ByteArray get() = if (family == afInet6) bytes.copyOfRange(8, 24) else bytes.copyOfRange(4, 8)

    /** The `sin6_scope_id` of an IPv6 address (host order), 0 for IPv4. */
    val scopeId: Int
        get() =
            if (family != afInet6 || bytes.size < 28) {
                0
            } else {
                bytes[24].u() or (bytes[25].u() shl 8) or (bytes[26].u() shl 16) or (bytes[27].u() shl 24)
            }

    /** An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as the IPv4 `sockaddr_in` it stands for; any other address as it is. */
    fun unmapped(): Sockaddr {
        if (family != afInet6) return this
        for (i in 8 until 18) if (bytes[i].toInt() != 0) return this
        if (bytes[18].u() != 0xff || bytes[19].u() != 0xff) return this
        return v4(bytes.copyOfRange(20, 24), port)
    }

    fun toInet(): InetSocketAddress = InetSocketAddress(ipText(ip), port)

    /** This address as the engines' [TcpAddress] (an IPv4-mapped one as IPv4). */
    fun toTcpAddress(): TcpAddress = unmapped().let { TcpAddress(it.ip, it.port, it.scopeId) }

    companion object {
        /** A `sockaddr_in` of the 4-byte [ip] and [port]. */
        fun v4(
            ip: ByteArray,
            port: Int,
        ): Sockaddr {
            val b = ByteArray(16)
            header(b, afInet, 16, port)
            ip.copyInto(b, 4)
            return Sockaddr(b)
        }

        /** A `sockaddr_in6` of the 16-byte [ip], [port] and [scopeId] (flow info 0). */
        fun v6(
            ip: ByteArray,
            port: Int,
            scopeId: Int,
        ): Sockaddr {
            val b = ByteArray(28)
            header(b, afInet6, 28, port)
            ip.copyInto(b, 8)
            for (i in 0 until 4) b[24 + i] = (scopeId ushr (8 * i)).toByte()
            return Sockaddr(b)
        }

        /** The `sockaddr` of [a]. */
        fun of(a: TcpAddress): Sockaddr = if (a.isIpv6) v6(a.bytes, a.port, a.scopeId) else v4(a.bytes, a.port)

        private fun header(
            b: ByteArray,
            family: Int,
            length: Int,
            port: Int,
        ) {
            if (bsdSockaddr) {
                b[0] = length.toByte()
                b[1] = family.toByte()
            } else {
                b[0] = family.toByte()
                b[1] = (family shr 8).toByte()
            }
            b[2] = (port shr 8).toByte()
            b[3] = port.toByte()
        }
    }
}

private fun Byte.u(): Int = toInt() and 0xff
