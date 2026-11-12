// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.tls.KslNet

/**
 * What the system knows about the source address it picks for a destination (Source(D) of RFC 6724 section 6): the
 * address, its on-link prefix length (null when the system does not tell), whether it is deprecated (RFC 4862) and whether
 * its interface is an encapsulating tunnel.
 */
@InternalKuicksilverApi
public class SourceInfo(
    /** The source address (port 0). */
    public val address: TcpAddress,
    /** The on-link prefix length of [address], null when unknown. */
    public val prefixLength: Int? = null,
    /** Whether [address] is deprecated (RFC 4862 section 5.5.4). */
    public val deprecated: Boolean = false,
    /** Whether the interface of [address] is an encapsulating tunnel (RFC 6724 section 6, Rule 7). */
    public val tunnel: Boolean = false,
)

/** [source]'s attributes as the system reports them (`ksl_addr_info`); without a report, only the address. */
@InternalKuicksilverApi
public fun localSourceInfo(source: TcpAddress): SourceInfo {
    val info = KslNet.addressInfo(source.bytes, source.scopeId)
    return SourceInfo(source.withPort(0), info?.prefixLength, info?.deprecated ?: false, info?.tunnel ?: false)
}

/**
 * Destination Address Selection of RFC 6724 section 6, which RFC 8305 section 4 makes the first step of Happy Eyeballs:
 * "First, the client MUST sort the addresses received up to this point using Destination Address Selection (\[RFC6724\],
 * Section 6)." The ten rules are applied in order, "If a rule determines a result, then the remaining rules are not
 * relevant and MUST be ignored", with the default policy table of section 2.1 and IPv4 addresses "represented as
 * IPv4-mapped addresses" (section 3.2). Source(D) is the address the system would send from ([sourceFor]: a connected UDP
 * socket, no packet sent), and its attributes come from [sourceInfo]:
 *
 * - Rule 1 (Source(D) undefined), 2 (scope), 5 (label), 6 (precedence), 8 (smaller scope) and 10 (the original order) need
 *   nothing more;
 * - Rule 3 (deprecated source) and Rule 7 (a tunnel, "an encapsulating transition mechanism") use what the system reports
 *   ([localSourceInfo]: Linux, macOS and Windows tell; elsewhere the source counts as preferred and native);
 * - Rule 4 (home addresses) never decides: no platform here has Mobile IPv6 home addresses;
 * - Rule 9 compares CommonPrefixLen(Source(D), D) up to the source's on-link prefix length, or 64 bits for IPv6 and 32 for
 *   IPv4 when the system does not report it.
 *
 * RFC 8305's RTT rule between Rules 8 and 9 applies "If the client is stateful and has a history of expected round-trip
 * times (RTTs) for the routes to access each address": the engines keep no per-address history, so there is none to add.
 * One instance memoizes Source(D) per destination; it is not thread-safe.
 */
@InternalKuicksilverApi
public class DestinationSort(
    private val sourceFor: (TcpAddress) -> TcpAddress? = ::sourceAddressFor,
    private val sourceInfo: (TcpAddress) -> SourceInfo = ::localSourceInfo,
) {
    private class Dest(
        val d: TcpAddress,
        val source: SourceInfo?,
    )

    private val known = HashMap<TcpAddress, SourceInfo?>()

    /** Forgets the sources found so far (a new network). */
    public fun clear() {
        known.clear()
    }

    /** [list] sorted by the rules of RFC 6724 section 6 (stable: Rule 10 keeps the original order of ties). */
    public fun sort(list: List<TcpAddress>): List<TcpAddress> {
        if (list.size < 2) return list
        val dests =
            list.map { a ->
                val key = a.withPort(0)
                val s = if (key in known) known[key] else sourceFor(key)?.let(sourceInfo).also { known[key] = it }
                Dest(a, s)
            }
        return dests.sortedWith { x, y -> compare(x, y) }.map { it.d }
    }

    /** Negative when [a] is preferred, positive when [b] is, 0 when no rule decides (Rule 10: the order stays). */
    private fun compare(
        a: Dest,
        b: Dest,
    ): Int {
        val sa = a.source
        val sb = b.source
        // Rule 1: Avoid unusable destinations.
        if (sa == null || sb == null) {
            if (sa != null) return -1
            if (sb != null) return 1
            // neither has a source: the rules that need none still apply (Rules 6 and 8), then Rule 10
            val p = policy(b.d).precedence.compareTo(policy(a.d).precedence)
            return if (p != 0) p else scope(a.d).compareTo(scope(b.d))
        }
        // Rule 2: Prefer matching scope.
        val scopeA = scope(a.d)
        val scopeB = scope(b.d)
        val matchA = scopeA == scope(sa.address)
        val matchB = scopeB == scope(sb.address)
        if (matchA != matchB) return if (matchA) -1 else 1
        // Rule 3: Avoid deprecated addresses.
        val depA = deprecated(sa)
        val depB = deprecated(sb)
        if (depA != depB) return if (depA) 1 else -1
        // Rule 4: Prefer home addresses: no Mobile IPv6 home or care-of addresses here, so it decides nothing.
        // Rule 5: Prefer matching label.
        val labelA = policy(sa.address).label == policy(a.d).label
        val labelB = policy(sb.address).label == policy(b.d).label
        if (labelA != labelB) return if (labelA) -1 else 1
        // Rule 6: Prefer higher precedence.
        val precA = policy(a.d).precedence
        val precB = policy(b.d).precedence
        if (precA != precB) return if (precA > precB) -1 else 1
        // Rule 7: Prefer native transport.
        if (sa.tunnel != sb.tunnel) return if (sa.tunnel) 1 else -1
        // Rule 8: Prefer smaller scope.
        if (scopeA != scopeB) return if (scopeA < scopeB) -1 else 1
        // Rule 9: Use longest matching prefix (same family only).
        if (a.d.isIpv6 == b.d.isIpv6) {
            val ca = commonPrefixLen(sa, a.d)
            val cb = commonPrefixLen(sb, b.d)
            if (ca != cb) return if (ca > cb) -1 else 1
        }
        // Rule 10: Otherwise, leave the order unchanged.
        return 0
    }

    public companion object {
        /** Scopes of RFC 4291 section 2.7, as RFC 6724 section 3.1 compares them. */
        internal const val SCOPE_LINK_LOCAL: Int = 0x2
        internal const val SCOPE_SITE_LOCAL: Int = 0x5
        internal const val SCOPE_GLOBAL: Int = 0xe

        /** A row of the policy table: prefix, its length in bits, Precedence and Label. */
        internal class Policy(
            val prefix: ByteArray,
            val bits: Int,
            val precedence: Int,
            val label: Int,
        )

        private fun row(
            bits: Int,
            precedence: Int,
            label: Int,
            vararg head: Int,
        ) = Policy(ByteArray(16).also { b -> head.forEachIndexed { i, v -> b[i] = v.toByte() } }, bits, precedence, label)

        /** The default policy table of RFC 6724 section 2.1, longest prefix first. */
        internal val DEFAULT_POLICY: List<Policy> =
            listOf(
                row(128, 50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), // ::1/128
                row(96, 35, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff), // ::ffff:0:0/96
                row(96, 1, 3), // ::/96
                row(32, 5, 5, 0x20, 0x01, 0, 0), // 2001::/32
                row(16, 30, 2, 0x20, 0x02), // 2002::/16
                row(16, 1, 12, 0x3f, 0xfe), // 3ffe::/16
                row(10, 1, 11, 0xfe, 0xc0), // fec0::/10
                row(7, 3, 13, 0xfc), // fc00::/7
                row(0, 40, 1), // ::/0
            ).sortedByDescending { it.bits }

        /** [a] as 16 bytes: an IPv4 address as its IPv4-mapped form (RFC 6724 section 3.2). */
        private fun mapped(a: TcpAddress): ByteArray {
            val b = a.bytes
            if (b.size == 16) return b
            return ByteArray(16).also {
                it[10] = 0xff.toByte()
                it[11] = 0xff.toByte()
                b.copyInto(it, 12)
            }
        }

        private fun matches(
            b: ByteArray,
            p: Policy,
        ): Boolean = leadingCommonBits(b, p.prefix, p.bits) >= p.bits

        /** Precedence(A) and Label(A): the longest matching row of the default table. */
        internal fun policy(a: TcpAddress): Policy {
            val b = mapped(a)
            return DEFAULT_POLICY.first { matches(b, it) }
        }

        /** Scope(A) by RFC 6724 sections 3.1 to 3.4. */
        internal fun scope(a: TcpAddress): Int {
            val b = a.bytes
            val b0 = b[0].toInt() and 0xff
            val b1 = b[1].toInt() and 0xff
            if (b.size == 4) {
                // 3.2: 169.254/16 and 127/8 are link-local, every other IPv4 address global
                return if (b0 == 127 || (b0 == 169 && b1 == 254)) SCOPE_LINK_LOCAL else SCOPE_GLOBAL
            }
            if ((0 until 15).all { b[it].toInt() == 0 } && b[15].toInt() == 1) return SCOPE_LINK_LOCAL // 3.4: ::1
            if (b0 == 0xff) return b1 and 0x0f // multicast: its scope field
            if (b0 == 0xfe && (b1 and 0xc0) == 0x80) return SCOPE_LINK_LOCAL // fe80::/10
            if (b0 == 0xfe && (b1 and 0xc0) == 0xc0) return SCOPE_SITE_LOCAL // fec0::/10
            return SCOPE_GLOBAL // global unicast, ULAs (3.1) and addresses with an IPv4 address embedded (3.3)
        }

        /** Whether [s] is deprecated: never an IPv4 source (3.2) nor IPv4-mapped, -compatible or -converted ones (3.3). */
        private fun deprecated(s: SourceInfo): Boolean = s.deprecated && s.address.isIpv6 && !embedsIpv4(s.address)

        private fun embedsIpv4(a: TcpAddress): Boolean {
            val b = a.bytes
            val v4mapped = (0 until 10).all { b[it].toInt() == 0 } && b[10].toInt() == -1 && b[11].toInt() == -1
            val compatible = (0 until 12).all { b[it].toInt() == 0 }
            val wkp = b[0].toInt() == 0 && b[1].toInt() == 0x64 && b[2].toInt() == -1 && b[3].toInt() == 0x9b.toByte().toInt()
            return v4mapped || compatible || wkp
        }

        /** CommonPrefixLen(S, D) of section 2.2: up to the length of S's prefix (64 or 32 bits when unknown). */
        internal fun commonPrefixLen(
            s: SourceInfo,
            d: TcpAddress,
        ): Int {
            val sb = s.address.bytes
            val db = d.bytes
            if (sb.size != db.size) return 0
            val limit = (s.prefixLength ?: if (sb.size == 16) 64 else 32).coerceIn(0, sb.size * 8)
            return leadingCommonBits(sb, db, limit)
        }

        /** The number of leading bits [a] and [b] share, at most [limit]. */
        private fun leadingCommonBits(
            a: ByteArray,
            b: ByteArray,
            limit: Int,
        ): Int {
            var bits = 0
            for (i in a.indices) {
                val x = (a[i].toInt() xor b[i].toInt()) and 0xff
                if (x == 0) {
                    bits += 8
                    if (bits >= limit) return limit
                    continue
                }
                return minOf(limit, bits + x.countLeadingZeroBits() - 24)
            }
            return minOf(limit, bits)
        }
    }
}

/**
 * [addrs] with the two families interleaved as RFC 8305 section 4 has it: "Whichever address family is first in the list
 * should be followed by an address of the other address family", after [firstFamilyCount] addresses of the first family
 * (the "First Address Family Count", 1 by default); the order within each family is kept.
 */
@InternalKuicksilverApi
public fun interleaveFamilies(
    addrs: List<TcpAddress>,
    firstFamilyCount: Int = 1,
): List<TcpAddress> {
    require(firstFamilyCount >= 1) { "firstFamilyCount must be at least 1, was $firstFamilyCount" }
    if (addrs.isEmpty()) return addrs
    val firstV6 = addrs.first().isIpv6
    val lead = addrs.filter { it.isIpv6 == firstV6 }
    val other = addrs.filter { it.isIpv6 != firstV6 }
    val out = ArrayList<TcpAddress>(addrs.size)
    var l = minOf(firstFamilyCount, lead.size)
    out.addAll(lead.subList(0, l))
    var o = 0
    while (l < lead.size || o < other.size) {
        if (o < other.size) out += other[o++]
        if (l < lead.size) out += lead[l++]
    }
    return out
}
