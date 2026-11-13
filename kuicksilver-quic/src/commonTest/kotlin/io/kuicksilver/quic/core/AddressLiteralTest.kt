// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ipBytesNoDns
import io.kuicksilver.quic.ipLiteral
import io.kuicksilver.quic.ipText
import io.kuicksilver.quic.withLiteralHost
import kotlin.test.Test
import kotlin.test.assertEquals

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

    /** RFC 5952 section 5: an address with an embedded IPv4 address under a well-known prefix in mixed notation. */
    @Test fun ipv4MappedAndTranslatedInMixedNotation() {
        assertEquals("::ffff:10.0.0.1", ipText(ip16(10 to -1, 11 to -1, 12 to 10, 15 to 1)))
        assertEquals("::ffff:0:10.0.0.1", ipText(ip16(8 to -1, 9 to -1, 12 to 10, 15 to 1)))
        assertEquals("::a00:1", ipText(ip16(12 to 10, 15 to 1))) // no well-known prefix: hex
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
