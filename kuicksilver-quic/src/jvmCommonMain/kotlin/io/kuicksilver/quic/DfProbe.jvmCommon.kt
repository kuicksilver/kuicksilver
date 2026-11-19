// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import java.nio.channels.DatagramChannel

/**
 * DF in probe mode on [ch] (`IP_MTU_DISCOVER` = `IP_PMTUDISC_PROBE`, and on an AF_INET6 socket `IPV6_MTU_DISCOVER` =
 * `IPV6_PMTUDISC_PROBE` with `IPV6_DONTFRAG`), which the JDK has no option for: the `KslFdSocket.DF_*` bits granted, 0 when
 * none (no means on this platform, or it refused). Never throws.
 */
internal expect fun dfProbe(ch: DatagramChannel): Int

/** `IP_MTU_DISCOVER` ([family] 4) or `IPV6_MTU_DISCOVER` (6) of [ch]; -1 when it cannot be read. For tests. */
internal expect fun dfModeOf(
    ch: DatagramChannel,
    family: Int,
): Int
