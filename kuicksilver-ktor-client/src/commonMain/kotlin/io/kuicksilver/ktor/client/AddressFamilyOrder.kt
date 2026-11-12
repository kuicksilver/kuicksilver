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
 * taken ([observe]); before any such lookup, or once it is older than [FRESH_MILLIS], a probe asks the system for a
 * source address of each family ([sourceAddressFor]: the first two rules of RFC 6724 section 6, on unusable destinations
 * and on matching scope), and IPv6 goes first only when it has a global one. [reset] forgets both on a new network.
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
     * IPv6 first when the system has a global IPv6 source address for a global destination; IPv4 first when IPv6 has
     * none, or only one that RFC 6724's default policy table ranks below IPv4 (Teredo `2001::/32`, 6to4 `2002::/16`,
     * unique local `fc00::/7`, link-local); IPv6 first when neither family has one (nothing to tell them apart).
     */
    private fun probe(): Boolean {
        val v6 = sourceFor(PROBE_V6)
        val v4 = sourceFor(PROBE_V4)
        return (v6 != null && isNativeGlobal(v6)) || v4 == null
    }

    companion object {
        /** The order of the process: the system's resolver and routes are the process's. */
        val system: AddressFamilyOrder = AddressFamilyOrder()

        /** How long an observed or probed order holds without a new one (a network change the engine cannot see). */
        const val FRESH_MILLIS: Long = 10 * 60_000L

        // global destinations only to ask the routing table: a connected UDP socket sends nothing
        private val PROBE_V6 =
            TcpAddress(byteArrayOf(0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88.toByte(), 0x88.toByte()), 53)
        private val PROBE_V4 = TcpAddress(byteArrayOf(8, 8, 8, 8), 53)

        /** A global unicast IPv6 address (`2000::/3`) other than Teredo (`2001::/32`) and 6to4 (`2002::/16`). */
        internal fun isNativeGlobal(a: TcpAddress): Boolean {
            val b = a.bytes
            if (b.size != 16 || (b[0].toInt() and 0xe0) != 0x20) return false
            val first16 = ((b[0].toInt() and 0xff) shl 8) or (b[1].toInt() and 0xff)
            val teredo = first16 == 0x2001 && b[2].toInt() == 0 && b[3].toInt() == 0
            return !teredo && first16 != 0x2002
        }
    }
}
