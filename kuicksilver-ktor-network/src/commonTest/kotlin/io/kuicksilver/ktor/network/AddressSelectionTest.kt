// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * RFC 6724 section 6 ([DestinationSort]) on the examples of its section 10.2, rule by rule, and the interleaving of RFC
 * 8305 section 4 ([interleaveFamilies]). Source(D) and its attributes are given by each test, as the system would.
 */
class AddressSelectionTest {
    /** An address from its text: dotted IPv4, or IPv6 in full or `::` form (enough for these tests). */
    private fun ip(text: String): TcpAddress {
        if ('.' in text && ':' !in text) return TcpAddress(text.split('.').map { it.toInt().toByte() }.toByteArray(), 443)
        val (head, tail) = if ("::" in text) text.split("::").let { it[0] to it[1] } else text to ""
        val h = if (head.isEmpty()) emptyList() else head.split(':')
        val t = if (tail.isEmpty()) emptyList() else tail.split(':')
        val groups = h + List(8 - h.size - t.size) { "0" } + t
        val b = ByteArray(16)
        groups.forEachIndexed { i, g ->
            val v = g.toInt(16)
            b[2 * i] = (v shr 8).toByte()
            b[2 * i + 1] = v.toByte()
        }
        return TcpAddress(b, 443)
    }

    /** A sort whose Source(D) comes from [sources] (destination text to source text; absent: undefined). */
    private fun sorter(
        sources: Map<String, String>,
        deprecated: Set<String> = emptySet(),
        tunnels: Set<String> = emptySet(),
        prefix: Map<String, Int> = emptyMap(),
    ): DestinationSort {
        val byDest = sources.entries.associate { ip(it.key).withPort(0) to it.value }
        return DestinationSort(
            sourceFor = { d -> byDest[d]?.let { ip(it).withPort(0) } },
            sourceInfo = { s ->
                val text = sources.values.first { ip(it).withPort(0) == s }
                SourceInfo(s, prefix[text], text in deprecated, text in tunnels)
            },
        )
    }

    private fun DestinationSort.order(vararg d: String): List<String> {
        val byAddr = d.associateBy { ip(it) }
        return sort(d.map { ip(it) }).map { byAddr.getValue(it) }
    }

    @Test fun rule2PreferMatchingScopeIpv6First() {
        val s = sorter(mapOf("2001:db8:1::1" to "2001:db8:1::2", "198.51.100.121" to "169.254.13.78"))
        assertEquals(listOf("2001:db8:1::1", "198.51.100.121"), s.order("198.51.100.121", "2001:db8:1::1"))
    }

    @Test fun negative_rule2LinkLocalIpv6SourcePutsIpv4First() {
        val s = sorter(mapOf("2001:db8:1::1" to "fe80::1", "198.51.100.121" to "198.51.100.117"))
        assertEquals(listOf("198.51.100.121", "2001:db8:1::1"), s.order("2001:db8:1::1", "198.51.100.121"))
    }

    @Test fun rule6PreferHigherPrecedence() {
        val s = sorter(mapOf("2001:db8:1::1" to "2001:db8:1::2", "10.1.2.3" to "10.1.2.4"))
        assertEquals(listOf("2001:db8:1::1", "10.1.2.3"), s.order("10.1.2.3", "2001:db8:1::1"))
    }

    @Test fun rule8PreferSmallerScope() {
        val s = sorter(mapOf("2001:db8:1::1" to "2001:db8:1::2", "fe80::1" to "fe80::2"))
        assertEquals(listOf("fe80::1", "2001:db8:1::1"), s.order("2001:db8:1::1", "fe80::1"))
    }

    @Test fun rule3AvoidDeprecatedAddresses() {
        val s = sorter(mapOf("2001:db8:1::1" to "2001:db8:1::2", "fe80::1" to "fe80::2"), deprecated = setOf("fe80::2"))
        assertEquals(listOf("2001:db8:1::1", "fe80::1"), s.order("fe80::1", "2001:db8:1::1"))
    }

    @Test fun negative_rule3NeverCountsAnIpv4SourceDeprecated() {
        // section 3.2: "IPv4 addresses MUST be treated as having "preferred" ... configuration status"
        val s = sorter(mapOf("192.0.2.1" to "192.0.2.9", "198.51.100.1" to "198.51.100.9"), deprecated = setOf("192.0.2.9"))
        assertEquals(listOf("192.0.2.1", "198.51.100.1"), s.order("192.0.2.1", "198.51.100.1"))
    }

    @Test fun rule9LongestMatchingPrefix() {
        val s = sorter(mapOf("2001:db8:1::1" to "2001:db8:1::2", "2001:db8:3ffe::1" to "2001:db8:3f44::2"))
        assertEquals(listOf("2001:db8:1::1", "2001:db8:3ffe::1"), s.order("2001:db8:3ffe::1", "2001:db8:1::1"))
    }

    @Test fun rule9StopsAtTheSourcesPrefixLength() {
        // both share at least 48 bits with their source and the prefixes are /48: no rule decides, the order stays
        val s =
            sorter(
                mapOf("2001:db8:1:1::1" to "2001:db8:1:1::2", "2001:db8:1:2::1" to "2001:db8:1:3::2"),
                prefix = mapOf("2001:db8:1:1::2" to 48, "2001:db8:1:3::2" to 48),
            )
        assertEquals(listOf("2001:db8:1:2::1", "2001:db8:1:1::1"), s.order("2001:db8:1:2::1", "2001:db8:1:1::1"))
        // with the usual /64 the first one matches longer
        val t = sorter(mapOf("2001:db8:1:1::1" to "2001:db8:1:1::2", "2001:db8:1:2::1" to "2001:db8:1:3::2"))
        assertEquals(listOf("2001:db8:1:1::1", "2001:db8:1:2::1"), t.order("2001:db8:1:2::1", "2001:db8:1:1::1"))
    }

    @Test fun rule5PreferMatchingLabel6to4() {
        val s = sorter(mapOf("2002:c633:6401::1" to "2002:c633:6401::2", "2001:db8:1::1" to "2002:c633:6401::2"))
        assertEquals(listOf("2002:c633:6401::1", "2001:db8:1::1"), s.order("2001:db8:1::1", "2002:c633:6401::1"))
    }

    @Test fun rule6NativeOver6to4WhenBothMatch() {
        val s = sorter(mapOf("2002:c633:6401::1" to "2002:c633:6401::2", "2001:db8:1::1" to "2001:db8:1::2"))
        assertEquals(listOf("2001:db8:1::1", "2002:c633:6401::1"), s.order("2002:c633:6401::1", "2001:db8:1::1"))
    }

    @Test fun rule1AvoidUnusableDestinations() {
        // an IPv4-only host: the IPv6 destination has no source and goes last whatever its precedence
        val s = sorter(mapOf("192.0.2.1" to "192.0.2.9"))
        assertEquals(listOf("192.0.2.1", "2001:db8::1"), s.order("2001:db8::1", "192.0.2.1"))
    }

    @Test fun negative_rule1BothUnusableStillByPrecedence() {
        val s = sorter(emptyMap())
        assertEquals(listOf("2001:db8::1", "192.0.2.1"), s.order("192.0.2.1", "2001:db8::1"))
    }

    @Test fun rule7PreferNativeTransport() {
        val s =
            sorter(
                mapOf("2001:db8:1::1" to "2001:db8:1::2", "2001:db8:2::1" to "2001:db8:9::2"),
                tunnels = setOf("2001:db8:1::2"),
            )
        assertEquals(listOf("2001:db8:2::1", "2001:db8:1::1"), s.order("2001:db8:1::1", "2001:db8:2::1"))
    }

    @Test fun rule10KeepsTheOrderOfTies() {
        val s = sorter(mapOf("192.0.2.1" to "10.0.0.2", "192.0.2.2" to "10.0.0.2", "192.0.2.3" to "10.0.0.2"))
        assertEquals(listOf("192.0.2.3", "192.0.2.1", "192.0.2.2"), s.order("192.0.2.3", "192.0.2.1", "192.0.2.2"))
    }

    @Test fun policiesAndScopes() {
        assertEquals(3, DestinationSort.policy(ip("fd00::1")).precedence)
        assertEquals(13, DestinationSort.policy(ip("fd00::1")).label)
        assertEquals(5, DestinationSort.policy(ip("2001::1")).precedence)
        assertEquals(50, DestinationSort.policy(ip("::1")).precedence)
        assertEquals(35, DestinationSort.policy(ip("192.0.2.1")).precedence) // as ::ffff:192.0.2.1 (section 3.2)
        assertEquals(4, DestinationSort.policy(ip("192.0.2.1")).label)
        assertEquals(40, DestinationSort.policy(ip("2001:db8::1")).precedence)
        assertEquals(1, DestinationSort.policy(ip("fec0::1")).precedence)
        assertEquals(DestinationSort.SCOPE_LINK_LOCAL, DestinationSort.scope(ip("127.0.0.1")))
        assertEquals(DestinationSort.SCOPE_LINK_LOCAL, DestinationSort.scope(ip("169.254.1.1")))
        assertEquals(DestinationSort.SCOPE_GLOBAL, DestinationSort.scope(ip("10.0.0.1")))
        assertEquals(DestinationSort.SCOPE_LINK_LOCAL, DestinationSort.scope(ip("::1")))
        assertEquals(DestinationSort.SCOPE_SITE_LOCAL, DestinationSort.scope(ip("fec0::1")))
        assertEquals(DestinationSort.SCOPE_GLOBAL, DestinationSort.scope(ip("fd00::1")))
        assertEquals(DestinationSort.SCOPE_GLOBAL, DestinationSort.scope(ip("64:ff9b::c000:201")))
    }

    @Test fun sourcesAreAskedOncePerDestination() {
        var asked = 0
        val s =
            DestinationSort(sourceFor = { d ->
                asked++
                d
            }, sourceInfo = { SourceInfo(it) })
        s.sort(listOf(ip("192.0.2.1"), ip("2001:db8::1")))
        s.sort(listOf(ip("192.0.2.1"), ip("2001:db8::1"), ip("2001:db8::2")))
        assertEquals(3, asked)
    }

    @Test fun loopbackSourceHasItsPrefixLength() {
        // the system's own report (ksl_addr_info): 127.0.0.1 is in 127/8
        assertEquals(8, localSourceInfo(TcpAddress(byteArrayOf(127, 0, 0, 1), 0)).prefixLength)
    }

    @Test fun interleavesWithAFirstAddressFamilyCount() {
        val v6 = (1..3).map { ip("2001:db8::$it") }
        val v4 = (1..3).map { ip("192.0.2.$it") }
        assertEquals(listOf(v6[0], v4[0], v6[1], v4[1], v6[2], v4[2]), interleaveFamilies(v6 + v4))
        assertEquals(listOf(v6[0], v6[1], v4[0], v6[2], v4[1], v4[2]), interleaveFamilies(v6 + v4, firstFamilyCount = 2))
        assertEquals(listOf(v4[0], v6[0], v4[1]), interleaveFamilies(listOf(v4[0], v4[1], v6[0])))
    }
}
