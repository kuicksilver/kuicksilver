// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.PacketBuffer

/** The SipHash key that spreads datagrams whose DCID names no loop over a group's loops: random per group, so a client cannot aim at one loop. */
internal class SipKey(
    val k0: Long,
    val k1: Long,
)

/**
 * Which loop of a group gets a datagram of the one socket the group shares when the kernel does not balance the port (the
 * in-process dispatch of `loops > 1`, docs/guide/quic.md "Several loops on one port"). The connection ID layout stays
 * [CidRoute]'s: a DCID in our format goes to the loop [CidRoute.ownerLoop] names (the routing byte, or with QUIC-LB the loop the
 * ID hashes to), so a migrated or rebound client reaches its connection with no forwarding. A long header (a client's Initial,
 * its 0-RTT and retransmissions, Version Negotiation) whose DCID names no loop goes to `SipHash(key, DCID) mod loops`: the same
 * DCID always to the same loop. A short header whose DCID names no loop, an owner past the group's loops (a stranger's routing
 * byte) and a datagram too short to carry a DCID go to loop 0; [CidRoute.resetCandidate] answers a Stateless Reset only for
 * an ID of the loop that checks it, so loop 0 never answers one for another loop's IDs (threat-model 3.4).
 *
 * Before any of that, a datagram that ends with a peer's reset token one of the loops' connections holds (`resets`) goes to
 * that loop: a Stateless Reset names no ID of ours (RFC 9000 section 10.3), and only the connection that holds the token can
 * take it (section 10.3.1). A packet of ours ending with such a token by chance (2^-128) only costs its loop a datagram it
 * forwards to the owner by ID.
 *
 * Reads the first octet, the long header's DCID length and the DCID; never throws on a short or malformed datagram. Sans-IO;
 * the dispatcher's thread calls it ([CidRoute.ownerLoop] reads only shared, thread-safe state).
 */
internal object DispatchRoute {
    /** Long header: first octet, version (4), DCID length (1). */
    private const val LONG_DCID_OFF = 6

    /** RFC 9000 section 17.2: a v1 DCID is at most 20 bytes; longer ones come from other versions and are hashed by their first 20. */
    private const val MAX_CID = 20

    fun loopOf(
        buf: PacketBuffer,
        len: Int,
        cidLength: Int,
        loops: Int,
        route: CidRoute,
        key: SipKey,
        resets: ResetTokenIndex? = null,
    ): Int {
        if (loops <= 1 || len < 1) return 0
        if (resets != null) resets.loopOf(buf, len).let { if (it in 0 until loops) return it }
        val first = buf[0].toInt() and 0xff
        if (first and 0x80 == 0) {
            // short header: the DCID has our length (RFC 9000 section 17.3); a datagram without room for it and one byte more is no packet
            if (len < 1 + cidLength + 1) return 0
            return route.ownerLoop(buf, 1, cidLength).let { if (it in 0 until loops) it else 0 }
        }
        if (len < LONG_DCID_OFF) return 0
        val dcidLen = buf[LONG_DCID_OFF - 1].toInt() and 0xff
        val n = if (dcidLen < MAX_CID) dcidLen else MAX_CID
        if (LONG_DCID_OFF + n > len) return 0
        val owner = route.ownerLoop(buf, LONG_DCID_OFF, n)
        if (n == dcidLen && owner in 0 until loops) return owner
        val h = SipHash.hash24(key.k0, key.k1, buf, LONG_DCID_OFF, n)
        return ((h ushr 1) % loops).toInt()
    }
}
