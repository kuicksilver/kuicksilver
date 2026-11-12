// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.sourceAddressFor
import kotlin.concurrent.Volatile

/**
 * Which address family goes first in a list of addresses the engine assembles itself (the A/AAAA records an HTTPS answer
 * carried, [RequestDns.seed]), where no resolver sorted them. RFC 8305 section 4: "First, the client MUST sort the
 * addresses received up to this point using Destination Address Selection ([RFC6724], Section 6)." The platform
 * resolvers sort their own answers so (getaddrinfo, Android's resolver), so the family a platform lookup put first is
 * taken ([observe]); on the desktop JVM that is the JDK's own order, IPv4 first unless `java.net.preferIPv6Addresses`
 * says otherwise, which is learned the same way. Before any such lookup, or once it is older than [FRESH_MILLIS], a probe
 * asks the system for a source address of each family ([sourceAddressFor]) and applies three rules of RFC 6724 section
 * 6 to a global destination of each family ([probe]). [reset] forgets both on a new network.
 *
 * This orders families only; [sort] is the one place an RFC 6724 sort of the engine's own would replace.
 */
internal class AddressFamilyOrder(
    private val clock: ExpiryClock = ExpiryClock(),
    /** The local address the system would send from to the destination, null for none (tests replace it). */
    private val sourceFor: (TcpAddress) -> TcpAddress? = ::sourceAddressFor,
) {
    private class Known(
        val ipv6First: Boolean,
        val at: ExpiryClock.Mark,
    )

    @Volatile
    private var observed: Known? = null

    @Volatile
    private var probed: Known? = null

    /** Takes the family order of a platform lookup's answer [list] when it has both families (its RFC 6724 sort). */
    fun observe(list: List<TcpAddress>) {
        if (list.any { it.isIpv6 } && list.any { !it.isIpv6 }) observed = Known(list.first().isIpv6, clock.mark())
    }

    /** Forgets what was observed and probed: a new network. */
    fun reset() {
        observed = null
        probed = null
    }

    /** Whether IPv6 goes first: as the last platform lookup ordered them, else as the probe finds. */
    fun ipv6First(): Boolean {
        observed?.takeIf { clock.elapsedMillis(it.at) < FRESH_MILLIS }?.let { return it.ipv6First }
        probed?.takeIf { clock.elapsedMillis(it.at) < FRESH_MILLIS }?.let { return it.ipv6First }
        return probe().also { probed = Known(it, clock.mark()) }
    }

    /**
     * [list] with the family [ipv6First] says first, each family in its order (no packet is sent to find out). The seam
     * for a destination address sort of the engine's own (RFC 6724 section 6).
     */
    fun sort(
        list: List<TcpAddress>,
        ipv6First: Boolean = ipv6First(),
    ): List<TcpAddress> {
        val lead = list.filter { it.isIpv6 == ipv6First }
        return if (lead.size == list.size || lead.isEmpty()) list else lead + list.filter { it.isIpv6 != ipv6First }
    }

    /**
     * Whether IPv6 goes first, by the source addresses the system picks for a global destination of each family, as
     * RFC 6724 section 6 compares two destinations:
     * - Rule 1, "If DB is known to be unreachable or if Source(DB) is undefined, then prefer DA.": the family without a
     *   source address goes last;
     * - Rule 2, "Prefer matching scope. If Scope(DA) = Scope(Source(DA)) and Scope(DB) <> Scope(Source(DB)), then prefer
     *   DA.": a link-local IPv6 source for a global destination puts IPv4 first;
     * - Rule 5, "Prefer matching label. If Label(Source(DA)) = Label(DA) and Label(Source(DB)) <> Label(DB), then prefer
     *   DA.": with the default policy table a Teredo (`2001::/32`), 6to4 (`2002::/16`) or unique local (`fc00::/7`)
     *   source has another label than a native global destination, while an IPv4 source matches an IPv4 destination's
     *   label, so IPv4 goes first ([isNativeGlobal]).
     * IPv6 first when neither family has a source address (nothing to tell them apart).
     */
    private fun probe(): Boolean {
        val v6 = sourceFor(PROBE_V6)
        val v4 = sourceFor(PROBE_V4)
        return (v6 != null && isNativeGlobal(v6)) || v4 == null
    }

    companion object {
        /** The order of the process: the system's resolver and routes are the process's. */
        val system: AddressFamilyOrder = AddressFamilyOrder()

        /**
         * Tests with a resolver of their own: a dual-stack host whatever the machine has (IPv6 first until a lookup says
         * otherwise), so engine tests do not depend on the IPv6 of the machine they run on.
         */
        fun dualStackForTest(): AddressFamilyOrder =
            AddressFamilyOrder(ExpiryClock { 0L }) { d ->
                if (d.isIpv6) {
                    TcpAddress(
                        byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
                        0,
                    )
                } else {
                    TcpAddress(byteArrayOf(192.toByte(), 0, 2, 1), 0)
                }
            }

        /** How long an observed or probed order holds without a new one (a network change the engine cannot see). */
        const val FRESH_MILLIS: Long = 10 * 60_000L

        // global destinations only to ask the routing table: a connected UDP socket sends nothing
        private val PROBE_V6 =
            TcpAddress(byteArrayOf(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88.toByte(), 0x88.toByte()), 53)
        private val PROBE_V4 = TcpAddress(byteArrayOf(8, 8, 8, 8), 53)

        /**
         * A global unicast IPv6 address (`2000::/3`) other than Teredo (`2001::/32`) and 6to4 (`2002::/16`): a source
         * whose label matches a native global destination's (RFC 6724 Rule 5; link-local and unique local addresses lie
         * outside `2000::/3`, the first by its scope, Rule 2).
         */
        internal fun isNativeGlobal(a: TcpAddress): Boolean {
            val b = a.bytes
            if (b.size != 16 || (b[0].toInt() and 0xe0) != 0x20) return false
            val first16 = ((b[0].toInt() and 0xff) shl 8) or (b[1].toInt() and 0xff)
            val teredo = first16 == 0x2001 && b[2].toInt() == 0 && b[3].toInt() == 0
            return !teredo && first16 != 0x2002
        }
    }
}
