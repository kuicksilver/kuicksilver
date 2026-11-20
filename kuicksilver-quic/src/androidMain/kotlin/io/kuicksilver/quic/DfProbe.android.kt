// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.FileDescriptor
import java.net.DatagramSocket
import java.net.Inet6Address
import java.nio.channels.DatagramChannel

// Linux values (android.system.OsConstants has none of them)
private const val IP_MTU_DISCOVER = 10
private const val IPV6_MTU_DISCOVER = 23
private const val IPV6_DONTFRAG = 62
private const val PMTUDISC_DO = 2
private const val PMTUDISC_PROBE = 3

/** The API level from which `ParcelFileDescriptor.fromDatagramSocket` returns a duplicate of the socket's descriptor. */
private const val FROM_DATAGRAM_SOCKET_DUPS = 29

/**
 * Through `android.system.Os` on the channel's descriptor: the options belong to the socket. From API 29 on a duplicate
 * (`ParcelFileDescriptor.fromDatagramSocket`) that is closed again. Up to API 28 `fromDatagramSocket` wraps the channel's own
 * descriptor instead (no duplicate), so closing it would close the channel: there the descriptor is borrowed as it is
 * (`DatagramSocket.getFileDescriptor$`, which every Android release has and hides from no app up to API 28) and never
 * closed here. No `ksl` needed. Per half probe mode, else DO mode.
 */
internal actual fun dfProbe(ch: DatagramChannel): Int =
    try {
        if (Build.VERSION.SDK_INT >= FROM_DATAGRAM_SOCKET_DUPS) {
            ParcelFileDescriptor.fromDatagramSocket(ch.socket())?.use { probe(it.fileDescriptor) } ?: -1
        } else {
            borrowedDescriptor(ch.socket())?.let(::probe) ?: -1
        }
    } catch (_: Exception) {
        DF_PROBE_FAILED // the duplicate of the descriptor failed (out of file descriptors): not a lasting lack of DF
    }

/** The channel's own descriptor (API 24 to 28), not to be closed; null when this runtime does not give it. */
private fun borrowedDescriptor(socket: DatagramSocket): FileDescriptor? =
    try {
        (DatagramSocket::class.java.getMethod("getFileDescriptor\$").invoke(socket) as? FileDescriptor)?.takeIf { it.valid() }
    } catch (_: Exception) {
        null
    }

private fun probe(fd: FileDescriptor): Int {
    val v6 = (Os.getsockname(fd) as? java.net.InetSocketAddress)?.address is Inet6Address
    var bits = 0
    // on AF_INET6: the v4-mapped half, which IPV6_MTU_DISCOVER does not cover
    bits =
        bits or
        when {
            set(fd, OsConstants.IPPROTO_IP, IP_MTU_DISCOVER, PMTUDISC_PROBE) -> DF_V4
            set(fd, OsConstants.IPPROTO_IP, IP_MTU_DISCOVER, PMTUDISC_DO) -> DF_V4_DO
            else -> 0
        }
    if (v6) {
        bits =
            bits or DF_INET6 or
            when {
                set(fd, OsConstants.IPPROTO_IPV6, IPV6_MTU_DISCOVER, PMTUDISC_PROBE) -> DF_V6
                set(fd, OsConstants.IPPROTO_IPV6, IPV6_MTU_DISCOVER, PMTUDISC_DO) -> DF_V6_DO
                else -> 0
            }
        set(fd, OsConstants.IPPROTO_IPV6, IPV6_DONTFRAG, 1)
    }
    return bits
}

/** -1: the public `android.system.Os` sets socket options but reads none of these (the device test reads the bits instead). */
internal actual fun dfModeOf(
    ch: DatagramChannel,
    family: Int,
): Int = -1

private fun set(
    fd: FileDescriptor,
    level: Int,
    option: Int,
    value: Int,
): Boolean =
    try {
        Os.setsockoptInt(fd, level, option, value)
        true
    } catch (_: ErrnoException) {
        false
    }

/** Null: Android's `SocketException` names the errno ("sendto failed: EMSGSIZE (Message too long)"). */
internal actual fun localizedEmsgsizeText(): String? = null
