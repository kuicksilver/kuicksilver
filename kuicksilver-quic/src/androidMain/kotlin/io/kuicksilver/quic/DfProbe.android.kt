// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.net.Inet6Address
import java.nio.channels.DatagramChannel

// Linux values (android.system.OsConstants has none of them)
private const val IP_MTU_DISCOVER = 10
private const val IPV6_MTU_DISCOVER = 23
private const val IPV6_DONTFRAG = 62
private const val PMTUDISC_DO = 2
private const val PMTUDISC_PROBE = 3

/**
 * Through `android.system.Os` on a duplicate of the channel's descriptor (`ParcelFileDescriptor.fromDatagramSocket`, as
 * `open` with a network does): the options belong to the socket, so they stay when the duplicate is closed. No `ksl`
 * needed. Per half probe mode, else DO mode.
 */
internal actual fun dfProbe(ch: DatagramChannel): Int =
    try {
        ParcelFileDescriptor.fromDatagramSocket(ch.socket()).use { pfd ->
            val fd = pfd.fileDescriptor
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
            bits
        }
    } catch (_: Exception) {
        DF_PROBE_FAILED // the duplicate of the descriptor failed (out of file descriptors): not a lasting lack of DF
    }

/** -1: the public `android.system.Os` sets socket options but reads none of these (the device test reads the bits instead). */
internal actual fun dfModeOf(
    ch: DatagramChannel,
    family: Int,
): Int = -1

private fun set(
    fd: java.io.FileDescriptor,
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
