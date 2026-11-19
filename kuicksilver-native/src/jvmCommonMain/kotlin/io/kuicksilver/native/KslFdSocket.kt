// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * `ksl_udp_fd_df_probe` / `ksl_udp_fd_df_mode` (additive under ABI 7) on a UDP socket `ksl` did not open: the JVM's portable
 * NIO socket. Call only once [KslLoader.isAvailable] said the library is loaded; kuicksilver-quic reaches it through
 * `io.kuicksilver.tls.KslSocketDf`.
 */
@InternalKuicksilverApi
public object KslFdSocket {
    /** The IPv4 half (an AF_INET6 socket: its v4-mapped traffic) is in probe mode (`IP_PMTUDISC_PROBE`). */
    public const val DF_V4: Int = 1

    /** The IPv6 half is in probe mode (`IPV6_PMTUDISC_PROBE`, with `IPV6_DONTFRAG`). */
    public const val DF_V6: Int = 2

    /** The socket is AF_INET6: it has both halves. */
    public const val DF_INET6: Int = 4

    /** The IPv4 half refused probe mode and has DF in DO mode (Linux `IP_PMTUDISC_DO`; Windows `IP_DONTFRAGMENT` alone). */
    public const val DF_V4_DO: Int = 8

    /** The IPv6 half refused probe mode and has DF in DO mode (Linux `IPV6_PMTUDISC_DO`; Windows `IPV6_DONTFRAG` alone). */
    public const val DF_V6_DO: Int = 16

    /**
     * The descriptor of an open JDK `DatagramChannel` (its `fdVal`; on Windows the SOCKET), or -1 where the runtime has no such
     * field. The value is the JDK's own and trusted as such: it is read through JNI, not checked, and only valid while the
     * channel is open (a closed channel's number may belong to another socket by then).
     */
    public fun channelFd(channel: java.nio.channels.DatagramChannel): Int = KslNative.udpChannelFd(channel)

    /**
     * DF on every datagram of the open socket [fd], replacing a mode set before: per half probe mode, else DO mode. The `DF_*`
     * bits of the result; 0 on Apple (no modes) and other platforms; -1 when [fd] is no IPv4 or IPv6 socket.
     */
    public fun dfProbe(fd: Long): Int = KslNative.udpFdDfProbe(fd)

    /**
     * `IP_MTU_DISCOVER` ([family] 4) or `IPV6_MTU_DISCOVER` (6) of the open socket [fd]: 3 PROBE (Linux 2 DO, 1 WANT, 0 DONT;
     * Windows 1 DO, 2 DONT, 0 NOT_SET); -1 unreadable or Apple.
     */
    public fun dfMode(
        fd: Long,
        family: Int,
    ): Int = KslNative.udpFdDfMode(fd, family)
}
