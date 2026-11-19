// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * `ksl_udp_fd_df_probe` / `ksl_udp_fd_df_mode` (additive under ABI 7) on a UDP socket `ksl` did not open: the JVM's portable
 * NIO socket. Call only once [KslLoader.isAvailable] said the library is loaded.
 */
@InternalKuicksilverApi
public object KslFdSocket {
    /** Granted: `IP_MTU_DISCOVER` = `IP_PMTUDISC_PROBE` (on an AF_INET6 socket: its v4-mapped half). */
    public const val DF_V4: Int = 1

    /** Granted: `IPV6_MTU_DISCOVER` = `IPV6_PMTUDISC_PROBE` (and `IPV6_DONTFRAG`) on an AF_INET6 socket. */
    public const val DF_V6: Int = 2

    /** The descriptor of a JDK `DatagramChannel` (its `fdVal`; on Windows the SOCKET), or -1 where the runtime has no such field. */
    public fun channelFd(channel: java.nio.channels.DatagramChannel): Int = KslNative.udpChannelFd(channel)

    /**
     * DF in probe mode on [fd], replacing a mode set before: the [DF_V4] and [DF_V6] bits granted, 0 where the system has no
     * probe mode (Apple) or refused it, -1 when [fd] is no IPv4 or IPv6 socket.
     */
    public fun dfProbe(fd: Long): Int = KslNative.udpFdDfProbe(fd)

    /** `IP_MTU_DISCOVER` ([family] 4) or `IPV6_MTU_DISCOVER` (6) of [fd]: 3 PROBE (Linux 2 DO, 1 WANT; Windows 1 DO); -1 unreadable or Apple. */
    public fun dfMode(
        fd: Long,
        family: Int,
    ): Int = KslNative.udpFdDfMode(fd, family)
}
