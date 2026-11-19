// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.io.IOException

/**
 * The system refused a datagram of [size] bytes, no more than QUIC's smallest allowed maximum datagram size (1200), as larger
 * than the path MTU it has cached for the peer (EMSGSIZE / WSAEMSGSIZE): a socket with DF in DO mode (probe mode refused, or
 * not available: the portable socket without `ksl`), after an ICMP Fragmentation Needed or Packet Too Big claimed less than
 * 1200, which RFC 9000 section 14.2.1 says to ignore. In DO mode the system enforces it all the same, so the path cannot carry
 * QUIC: the endpoint loop closes the connection ([QuicException.ConnectionLost.NoViablePath]), which an HTTP/3 client answers
 * with its fallback to TCP, instead of losing every datagram until the idle timeout.
 */
internal class PathMtuRefusedException(
    val size: Int,
    cause: Throwable? = null,
) : IOException("the system refused a $size-byte datagram as above the path MTU it cached (EMSGSIZE)", cause)

/** QUIC's smallest allowed maximum datagram size (RFC 9000 section 14): a refusal at or below it fails the path. */
internal const val PATH_MTU_FLOOR = 1200
