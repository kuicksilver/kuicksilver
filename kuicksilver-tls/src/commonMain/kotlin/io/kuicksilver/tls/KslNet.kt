// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader

/**
 * The system's resolver one address family at a time (`ksl_resolve`: `getaddrinfo` with `AF_INET` or `AF_INET6`) and what
 * the system knows about one of its own addresses (`ksl_addr_info`), for Happy Eyeballs (RFC 8305 sections 3 and 4) on the
 * JVM and Android, where `InetAddress` asks for both families in one call and tells nothing about local addresses. Both
 * calls block their thread; the caller runs them where that is acceptable.
 */
@InternalKuicksilverApi
public object KslNet {
    /** One address of [resolve]: 4 or 16 bytes and, for a link-local IPv6 address, its zone. */
    public class Address(
        /** The address in network order: 4 bytes (IPv4) or 16 (IPv6). */
        public val bytes: ByteArray,
        /** The IPv6 scope (zone) id; 0 for none. */
        public val scopeId: Int,
    )

    /** What [addressInfo] found about a local address. */
    public class Info(
        /** The on-link prefix length of the address (its netmask), null when the system does not tell. */
        public val prefixLength: Int?,
        /** Whether the address is deprecated (RFC 4862 section 5.5.4), as far as the system tells. */
        public val deprecated: Boolean,
        /** Whether its interface is an encapsulating tunnel (6in4, 6rd, ISATAP, GRE, IP in IPv6), as far as the system tells. */
        public val tunnel: Boolean,
    )

    /** Replaces the native calls (tests). */
    internal var resolveForTest: ((String, Int) -> ByteArray?)? = null

    /** Whether the native library, and so [resolve] and [addressInfo], can be used in this process (never throws). */
    public fun available(): Boolean = resolveForTest != null || KslLoader.isAvailable()

    /**
     * The addresses of [name] of one family ([ipv6]) in the resolver's order: empty when the name has none of that family
     * (or does not exist), null when the lookup failed or the library cannot be used.
     */
    public fun resolve(
        name: String,
        ipv6: Boolean,
    ): List<Address>? {
        val family = if (ipv6) KslConst.ADDR_V6 else KslConst.ADDR_V4
        val raw =
            try {
                resolveForTest?.invoke(name, family) ?: if (KslLoader.isAvailable()) Ksl.resolve(name, family) else null
            } catch (e: Throwable) {
                if (e !is Exception && !isLinkageError(e)) throw e
                null
            } ?: return null
        return decode(raw, family)
    }

    internal fun decode(
        raw: ByteArray,
        family: Int,
    ): List<Address>? {
        val n = KslConst.RESOLVE_ENTRY_LEN
        if (raw.size % n != 0) return null
        val out = ArrayList<Address>(raw.size / n)
        for (p in raw.indices step n) {
            if (raw[p].toInt() != family) return null
            val size = if (family == KslConst.ADDR_V6) 16 else 4
            val scope = (17 until 21).fold(0) { v, i -> v shl 8 or (raw[p + i].toInt() and 0xff) }
            out += Address(raw.copyOfRange(p + 1, p + 1 + size), scope)
        }
        return out
    }

    /**
     * The IPv6 addresses the platform itself synthesizes for the IPv4 address [v4] with its NAT64 prefixes (Apple's
     * `getaddrinfo` with `AI_DEFAULT`): empty when it synthesizes none (no NAT64 network), null where the platform has no
     * such call or the library cannot be used.
     */
    public fun nat64Synthesize(v4: ByteArray): List<ByteArray>? {
        val raw =
            try {
                if (KslLoader.isAvailable()) Ksl.nat64Synthesize(v4) else null
            } catch (e: Throwable) {
                if (e !is Exception && !isLinkageError(e)) throw e
                null
            } ?: return null
        return (0 until raw.size / 16).map { raw.copyOfRange(it * 16, it * 16 + 16) }
    }

    /**
     * What the system knows about [address] (4 or 16 bytes, [scopeId] its zone or 0), one of this host's own addresses:
     * null when no interface has it, its interfaces cannot be read or the library cannot be used.
     */
    public fun addressInfo(
        address: ByteArray,
        scopeId: Int,
    ): Info? {
        val raw =
            try {
                if (KslLoader.isAvailable()) Ksl.addrInfo(address, scopeId) else null
            } catch (e: Throwable) {
                if (e !is Exception && !isLinkageError(e)) throw e
                null
            }
        if (raw == null || raw.size != 2) return null
        return Info(
            raw[0].takeIf { it >= 0 },
            raw[1] and KslConst.ADDR_DEPRECATED != 0,
            raw[1] and KslConst.ADDR_TUNNEL != 0,
        )
    }
}
