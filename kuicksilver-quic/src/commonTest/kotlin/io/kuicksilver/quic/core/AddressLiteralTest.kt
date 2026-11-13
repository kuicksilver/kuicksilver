// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ipBytesNoDns
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.ipText
import io.kuicksilver.quic.sameIpAs
import io.kuicksilver.quic.withLiteralHost
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `InetSocketAddress.hostname` is `java.net.InetSocketAddress.getHostName()` on the JVM and Android: for an address made from a
 * literal it performs a reverse DNS lookup (10 s on an emulator without a resolver). The connect, bind and request paths use the
 * literal built from the address bytes instead.
 */
@OptIn(InternalKuicksilverApi::class)
class AddressLiteralTest {
    @Test fun ipv4LiteralFromBytes() {
        assertEquals("10.0.0.1", InetSocketAddress("10.0.0.1", 1111).ipLiteral())
    }

    @Test fun ipv6LiteralIsCanonical() {
        assertEquals("::1", InetSocketAddress("0:0:0:0:0:0:0:1", 443).ipLiteral())
        assertEquals("fe80::1", InetSocketAddress("fe80:0:0:0:0:0:0:1", 1).ipLiteral())
    }

    @Test fun ipv6IsRfc5952OnEveryPlatform() {
        assertEquals("2001:db8::1", InetSocketAddress("2001:0DB8:0:0:0:0:0:1", 443).ipLiteral())
        assertEquals("2001:db8::1:0:0:1", InetSocketAddress("2001:db8:0:0:1:0:0:1", 443).ipLiteral()) // the first of equal runs
        assertEquals("2001:db8:0:1:1:1:1:1", InetSocketAddress("2001:db8::1:1:1:1:1", 443).ipLiteral()) // one zero group stays
    }

    /**
     * RFC 5952 section 5: an address with an embedded IPv4 address under a well-known prefix (RFC 4291, RFC 2765) in mixed
     * notation; the IPv4-compatible `::/96` only when its 13th and 14th bytes are not both zero, as `inet_ntop` decides.
     */
    @Test fun ipv4MappedTranslatedAndCompatibleInMixedNotation() {
        assertEquals("::ffff:10.0.0.1", ipText(ip16(10 to -1, 11 to -1, 12 to 10, 15 to 1)))
        assertEquals("::ffff:0:10.0.0.1", ipText(ip16(8 to -1, 9 to -1, 12 to 10, 15 to 1)))
        assertEquals("::10.0.0.1", ipText(ip16(12 to 10, 15 to 1))) // IPv4-compatible (RFC 4291 section 2.5.5.1)
        assertEquals("::0.1.0.0", ipText(ip16(13 to 1)))
        assertEquals("::", ipText(ByteArray(16))) // the unspecified address stays hexadecimal
        assertEquals("::1", ipText(ip16(15 to 1))) // and so does the loopback
        assertEquals("::102", ipText(ip16(14 to 1, 15 to 2))) // bytes 13 and 14 zero: hexadecimal
        assertEquals("1::", ipText(ip16(1 to 1))) // a trailing zero run
        assertEquals("2001:db8::", ipText(ip16(0 to 0x20, 1 to 1, 2 to 0x0d, 3 to 0xb8)))
        assertEquals("10.0.0.1", ipText(byteArrayOf(9, 10, 0, 0, 1), 1, 4)) // at an offset
        // java.net makes an IPv4-mapped literal an Inet4Address (4 bytes); Kotlin/Native keeps the 16 bytes
        for (text in listOf("::ffff:10.0.0.1", "::ffff:a00:1", "0:0:0:0:0:ffff:a00:1")) {
            val a = InetSocketAddress(text, 443)
            val expected = if (a.ipBytesNoDns()!!.size == 16) "::ffff:10.0.0.1" else "10.0.0.1"
            assertEquals(expected, a.ipLiteral(), text)
        }
    }

    /** A zone ID stays (RFC 4007 section 11), as java.net's own literal and Netty's `hostString` keep it. */
    @Test fun ipv6ZoneIsKept() {
        assertEquals("fe80::1%1", InetSocketAddress("fe80:0:0:0:0:0:0:1%1", 443).ipLiteral())
        assertEquals("fe80::1%1", InetSocketAddress("fe80::1%1", 443).ipLiteral())
        // an interface name: java.net keeps it when the interface exists and leaves the address unresolved otherwise
        assertEquals("fe80::1%en0", InetSocketAddress("fe80::1%en0", 443).ipLiteral())
        assertEquals("fe80::1", InetSocketAddress("fe80::1", 443).ipLiteral())
        assertEquals("fe80::1%0", InetSocketAddress("fe80::1%0", 443).ipLiteral()) // an explicit zone 0 too, as java.net writes it
    }

    /** One address however written, a different port, address or zone is another; never a lookup. */
    @Test fun sameIpAsComparesBytesPortAndZone() {
        assertTrue(InetSocketAddress("2001:db8::1", 443).sameIpAs(InetSocketAddress("2001:DB8:0:0:0:0:0:1", 443)))
        assertTrue(InetSocketAddress("10.0.0.1", 443).sameIpAs(InetSocketAddress("10.0.0.1", 443)))
        assertFalse(InetSocketAddress("2001:db8::1", 443).sameIpAs(InetSocketAddress("2001:db8::1", 444)))
        assertFalse(InetSocketAddress("2001:db8::1", 443).sameIpAs(InetSocketAddress("2001:db8::2", 443)))
        assertFalse(InetSocketAddress("fe80::1%1", 443).sameIpAs(InetSocketAddress("fe80::1%2", 443)))
        assertTrue(InetSocketAddress("fe80::1%1", 443).sameIpAs(InetSocketAddress("fe80:0:0:0:0:0:0:1%1", 443)))
    }

    /** An IPv4-mapped address is its IPv4 address on every platform (java.net makes it one, Kotlin/Native keeps 16 bytes). */
    @Test fun sameIpAsUnmapsIpv4MappedAddresses() {
        assertTrue(InetSocketAddress("::ffff:10.0.0.1", 443).sameIpAs(InetSocketAddress("10.0.0.1", 443)))
        assertTrue(InetSocketAddress("10.0.0.1", 443).sameIpAs(InetSocketAddress("0:0:0:0:0:ffff:a00:1", 443)))
        assertFalse(InetSocketAddress("::ffff:10.0.0.1", 443).sameIpAs(InetSocketAddress("10.0.0.2", 443)))
        assertFalse(InetSocketAddress("::10.0.0.1", 443).sameIpAs(InetSocketAddress("10.0.0.1", 443))) // IPv4-compatible is not
    }

    /** The zone comparison agrees with the literal ([ipLiteral]): the text of the zone decides, `%0` included. */
    @Test fun sameIpAsAgreesWithTheLiteralOnZones() {
        val cases =
            listOf(
                "fe80::1" to "fe80::1",
                "fe80::1%0" to "fe80::1",
                "fe80::1%0" to "fe80::1%0",
                "fe80::1%1" to "fe80::1%1",
                "fe80::1%1" to "fe80::1%0",
                "fe80::1%en0" to "fe80::1%en0",
                "fe80::1%en0" to "fe80::1%1",
            )
        for ((x, y) in cases) {
            val a = InetSocketAddress(x, 443)
            val b = InetSocketAddress(y, 443)
            assertEquals(a.ipLiteral() == b.ipLiteral(), a.sameIpAs(b), "$x vs $y: ${a.ipLiteral()} / ${b.ipLiteral()}")
            assertEquals(a.ipLiteral() == b.ipLiteral(), b.sameIpAs(a), "$y vs $x")
        }
    }

    /** 16 zero bytes with the given (index, value) set. */
    private fun ip16(vararg set: Pair<Int, Int>): ByteArray = ByteArray(16).also { b -> for ((i, v) in set) b[i] = v.toByte() }

    @Test fun withLiteralHostKeepsThePortAndResolvesToTheSameBytes() {
        val a = InetSocketAddress("0.0.0.0", 4433).withLiteralHost(5555)
        assertEquals(5555, a.port)
        assertEquals("0.0.0.0", a.ipLiteral())
        assertEquals(InetSocketAddress("0.0.0.0", 5555), a)
    }
}
