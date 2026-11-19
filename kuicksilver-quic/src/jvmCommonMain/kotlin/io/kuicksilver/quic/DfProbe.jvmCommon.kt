// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import java.nio.channels.DatagramChannel

// the bits of dfProbe (ksl.h KSL_FD_DF_*)
internal const val DF_V4 = 1
internal const val DF_V6 = 2
internal const val DF_INET6 = 4
internal const val DF_V4_DO = 8
internal const val DF_V6_DO = 16

/**
 * DF on every datagram of the open channel [ch], which the JDK cannot put in probe mode: per half (IPv4, and the IPv6 half of
 * an AF_INET6 socket) probe mode (`IP_PMTUDISC_PROBE` / `IPV6_PMTUDISC_PROBE`) where the system takes it, else DO mode. The
 * `DF_*` bits of the result; 0 where nothing was set (Apple: no modes); -1 when there is no means here (the JVM without
 * `ksl`, a runtime without the channel's descriptor). Never throws.
 */
internal expect fun dfProbe(ch: DatagramChannel): Int

/** `IP_MTU_DISCOVER` ([family] 4) or `IPV6_MTU_DISCOVER` (6) of the open channel [ch]; -1 when it cannot be read. For tests. */
internal expect fun dfModeOf(
    ch: DatagramChannel,
    family: Int,
): Int

/**
 * The system's own text for EMSGSIZE in this process's locale (`strerror`, through `ksl` on the JVM), which the JDK puts in a
 * send's `SocketException` on Linux; null where it is not known (no `ksl`, Windows, Android, whose text names EMSGSIZE).
 */
internal expect fun localizedEmsgsizeText(): String?

/** Every half of the socket in probe mode. */
internal fun probeComplete(bits: Int): Boolean = bits > 0 && bits and DF_V4 != 0 && (bits and DF_INET6 == 0 || bits and DF_V6 != 0)

/** Every half of the socket has DF, in probe or DO mode. */
internal fun dfComplete(bits: Int): Boolean =
    bits > 0 && bits and (DF_V4 or DF_V4_DO) != 0 && (bits and DF_INET6 == 0 || bits and (DF_V6 or DF_V6_DO) != 0)
