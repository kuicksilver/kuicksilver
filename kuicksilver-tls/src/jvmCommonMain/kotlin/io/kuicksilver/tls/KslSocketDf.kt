// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslFdSocket
import io.kuicksilver.native.KslLoader
import java.nio.channels.DatagramChannel

/**
 * DF on the portable NIO socket through `ksl` (ADR-0004: kuicksilver-quic reaches the native library only through
 * kuicksilver-tls, as [KslUdpSocket] for the accelerated socket). The descriptor comes from the JDK's own `fdVal`, read
 * through JNI; [apply] and [mode] are only for an open channel. Using either loads `ksl` (once per process) if it is not
 * loaded yet.
 */
@InternalKuicksilverApi
public object KslSocketDf {
    /** Probe mode on the IPv4 half. */
    public const val V4: Int = KslFdSocket.DF_V4

    /** Probe mode on the IPv6 half. */
    public const val V6: Int = KslFdSocket.DF_V6

    /** The socket is AF_INET6 (both halves). */
    public const val INET6: Int = KslFdSocket.DF_INET6

    /** DO mode on the IPv4 half (probe refused). */
    public const val V4_DO: Int = KslFdSocket.DF_V4_DO

    /** DO mode on the IPv6 half (probe refused). */
    public const val V6_DO: Int = KslFdSocket.DF_V6_DO

    /**
     * DF on every datagram of the open [channel]: per half probe mode, else DO mode; the bits of the result, 0 where `ksl` sets
     * nothing (Apple), -1 when it cannot be asked (no library, a library without these entry points, a runtime whose channel
     * has no `fdVal`, no IP socket). Never throws.
     */
    public fun apply(channel: DatagramChannel): Int = withFd(channel) { fd -> KslFdSocket.dfProbe(fd) }

    /** `strerror(EMSGSIZE)` in the process's locale (the JDK's text for it on Linux and Apple); null without `ksl` or on Windows. */
    public fun emsgsizeText(): String? =
        try {
            if (KslLoader.isAvailable()) KslFdSocket.emsgsizeText() else null
        } catch (_: LinkageError) {
            null
        }

    /** `IP_MTU_DISCOVER` ([family] 4) or `IPV6_MTU_DISCOVER` (6) of the open [channel]; -1 when it cannot be read. */
    public fun mode(
        channel: DatagramChannel,
        family: Int,
    ): Int = withFd(channel) { fd -> KslFdSocket.dfMode(fd, family) }

    private inline fun withFd(
        channel: DatagramChannel,
        block: (Long) -> Int,
    ): Int =
        try {
            if (!KslLoader.isAvailable()) {
                -1
            } else {
                val fd = KslFdSocket.channelFd(channel)
                if (fd < 0) -1 else block(fd.toLong())
            }
        } catch (_: LinkageError) {
            -1 // a library without these entry points
        }
}
