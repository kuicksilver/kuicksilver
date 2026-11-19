// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.io.IOException

/**
 * The system refused a datagram of [size] bytes, no more than QUIC's smallest allowed maximum datagram size (1200), as larger
 * than the path MTU it has cached for the peer (EMSGSIZE / WSAEMSGSIZE): a socket with DF in DO mode (probe mode refused, or
 * not available: the portable socket without `ksl`), after an ICMP Fragmentation Needed or Packet Too Big claimed less than
 * 1200, which RFC 9000 section 14.2.1 says to ignore. In DO mode the system enforces it all the same, so that path cannot carry
 * QUIC (section 14: "cease sending QUIC packets ... on the affected path"): the endpoint loop closes the path when it is not
 * the connection's active one, else the connection with a CONNECTION_CLOSE of NO_VIABLE_PATH (an HTTP/3 client falls back to
 * TCP), instead of losing every datagram until the idle timeout. [destination]: where the refused datagram went, when known.
 * [cause] is the system's own refusal (the JDK's `SocketException`), and the message names EMSGSIZE and "Message too long",
 * so code that recognises a refusal as too large by its text (the CONNECT-UDP proxy) sees it as one.
 * The portable socket throws it only after a retry was refused too: a connected socket's one-shot socket error from an ICMP
 * message (Linux `sk_err`, even in probe mode) passes the retry.
 */
internal class PathMtuRefusedException(
    val size: Int,
    val destination: io.ktor.network.sockets.InetSocketAddress? = null,
    cause: Throwable? = null,
) : IOException("the system refused a $size-byte datagram as above the path MTU it cached (EMSGSIZE: Message too long)", cause)

/** QUIC's smallest allowed maximum datagram size (RFC 9000 section 14): a refusal at or below it fails the path. */
internal const val PATH_MTU_FLOOR = 1200

/**
 * A socket with an address family it cannot set DF for (no DF, no QUIC: RFC 9000 section 14): the NIO socket on a dual-stack
 * channel with one half without DF, or an AF_INET channel (no IPv6 at all). A server drops Initials from that family before
 * any state; a send there is refused slot by slot ([takeDfRefusals]).
 */
internal interface DfFamilyRestricted {
    /** The family without DF, or null. */
    val noDfFamily: IpFamily?

    /** The destinations whose datagrams the latest sends refused for want of DF since the previous call (cleared), or empty. */
    fun takeDfRefusals(): List<io.ktor.network.sockets.InetSocketAddress>
}

/** The address family of [a]: an IPv4-mapped IPv6 address counts as IPv4; null for a name. */
internal fun ipFamilyOf(a: io.ktor.network.sockets.InetSocketAddress): IpFamily? {
    val b = a.ipBytesNoDns() ?: return null
    if (b.size == 4) return IpFamily.V4
    for (i in 0 until 10) if (b[i].toInt() != 0) return IpFamily.V6
    return if (b[10].toInt() == -1 && b[11].toInt() == -1) IpFamily.V4 else IpFamily.V6
}
