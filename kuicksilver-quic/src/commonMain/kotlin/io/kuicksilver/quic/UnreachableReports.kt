// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * A socket that reports ICMP port and host unreachable messages for the datagrams it sent: the accelerated socket on Linux and
 * Android with Don't Fragment (the error queue, `ksl_udp_take_unreachable`); no other socket. A CONNECT-UDP proxy closes a
 * tunnel whose target is unreachable (RFC 9298 section 3.1: a socket "no longer usable").
 */
@InternalKuicksilverApi
public interface UnreachableReports {
    /** The destination of the latest unreachable since the last call, or null when none arrived. One thread at a time. */
    public fun takeUnreachable(): InetSocketAddress?
}
