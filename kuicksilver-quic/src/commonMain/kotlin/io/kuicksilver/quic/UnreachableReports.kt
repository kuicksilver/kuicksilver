// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi

/**
 * A socket that reports ICMP port and host unreachable messages for the datagrams it sent: the accelerated socket on Linux and
 * Android with Don't Fragment (the error queue, `ksl_udp_take_unreachable`); no other socket. A CONNECT-UDP proxy closes a
 * tunnel whose target is unreachable (RFC 9298 section 3.1: a socket "no longer usable") once the report is checked against
 * what it sent (RFC 8085 section 5.2).
 */
@InternalKuicksilverApi
public interface UnreachableReports {
    /** The oldest queued report, or null when none is. One thread at a time. */
    public fun takeUnreachable(): Unreachable?
}

/**
 * An ICMP unreachable for a datagram sent to [destination]: a port unreachable ([port]) or a host (ICMPv6 address)
 * unreachable, and the start of that datagram's payload as the message quoted it ([quote]; empty when it quoted the
 * headers only, at most 64 bytes).
 */
@InternalKuicksilverApi
public class Unreachable(
    public val destination: InetSocketAddress,
    public val port: Boolean,
    public val quote: ByteArray,
)
