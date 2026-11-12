// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Which address family leads in the lists the engine assembles (RFC 8305 section 4; RFC 6724 section 6, Rules 1, 2 and 5). */
class AddressFamilyOrderTest {
    private fun v4(last: Int) = TcpAddress(byteArrayOf(192.toByte(), 0, 2, last.toByte()), 0)

    private fun v6(vararg head: Int) =
        TcpAddress(
            ByteArray(16).also { b ->
                head.forEachIndexed { i, x -> b[i] = x.toByte() }
                b[15] = 1
            },
            0,
        )

    private fun order(
        v6Source: TcpAddress?,
        v4Source: TcpAddress?,
        now: () -> Long = { 0L },
    ): Pair<AddressFamilyOrder, IntArray> {
        val probes = IntArray(1)
        return AddressFamilyOrder(ExpiryClock(now)) { d ->
            probes[0]++
            if (d.isIpv6) v6Source else v4Source
        } to probes
    }

    @Test fun negative_ipv4OnlyHostPutsIpv4First() { // RFC 6724 Rule 1: an IPv6 destination without a source is unusable
        val (o, _) = order(null, v4(100))
        assertFalse(o.ipv6First())
        assertEquals(listOf(v4(1), v6(0x20, 0x01)).map { it.toString() }, o.sort(listOf(v6(0x20, 0x01), v4(1))).map { it.toString() })
    }

    @Test fun dualStackHostPutsIpv6First() {
        assertTrue(order(v6(0x20, 0x01, 0x0d, 0xb8), v4(100)).first.ipv6First())
        assertTrue(order(v6(0x26, 0x00), null).first.ipv6First()) // IPv6-only
        assertTrue(order(null, null).first.ipv6First()) // nothing to tell them apart
    }

    @Test fun negative_ipv6SourceOfAnotherScopeOrLabelPutsIpv4First() {
        // RFC 6724 Rule 2 (a link-local source for a global destination) and Rule 5 (a unique local, Teredo or 6to4 source,
        // whose label differs from a native global destination's): IPv4 goes first
        for (source in listOf(v6(0xfe, 0x80), v6(0xfd, 0x00), v6(0x20, 0x01, 0, 0), v6(0x20, 0x02))) {
            assertFalse(order(source, v4(100)).first.ipv6First(), "$source")
        }
    }

    @Test fun platformLookupsOrderWinsOverTheProbe() {
        val (o, probes) = order(v6(0x20, 0x01, 0x0d, 0xb8), v4(100))
        o.observe(listOf(v4(1), v6(0x20, 0x01))) // the resolver sorted IPv4 first
        assertFalse(o.ipv6First())
        assertEquals(0, probes[0])
        o.observe(listOf(v4(1))) // one family says nothing about the order
        assertFalse(o.ipv6First())
        o.reset() // a new network: probed again
        assertTrue(o.ipv6First())
        assertEquals(2, probes[0])
    }

    @Test fun negative_observedOrderExpires() {
        var now = 0L
        val (o, probes) = order(null, v4(100)) { now }
        o.observe(listOf(v6(0x20, 0x01), v4(1)))
        assertTrue(o.ipv6First())
        now = AddressFamilyOrder.FRESH_MILLIS // older than it may be: the probe answers, and is kept as long
        assertFalse(o.ipv6First())
        assertFalse(o.ipv6First())
        assertEquals(2, probes[0])
    }
}
