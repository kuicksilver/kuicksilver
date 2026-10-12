// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

/** On Kotlin/Native the loop reads address bytes from the text of an IP literal; it never asks the resolver. */
class AddressClassNativeTest {
    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    @Test fun ipBytesNeverResolvesHostnames() {
        assertContentEquals("localhost".encodeToByteArray(), AddressClass.ipBytes(InetSocketAddress("localhost", 1)))
    }

    @Test fun ipv4LiteralsAreParsed() {
        assertContentEquals(bytes(10, 0, 0, 1), AddressClass.ipBytes(InetSocketAddress("10.0.0.1", 1)))
        assertContentEquals(bytes(255, 255, 255, 255), AddressClass.ipBytes(InetSocketAddress("255.255.255.255", 1)))
    }

    @Test fun ipv6SpellingsOfOneAddressGiveTheSameBytes() {
        val loop = ByteArray(16).also { it[15] = 1 }
        for (s in listOf("::1", "0:0:0:0:0:0:0:1", "0000::0001", "[::1]")) {
            assertContentEquals(loop, AddressClass.ipBytes(InetSocketAddress(s, 1)), s)
        }
        assertContentEquals(
            bytes(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1),
            AddressClass.ipBytes(InetSocketAddress("::ffff:192.0.2.1", 1)),
        )
        assertContentEquals(
            bytes(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
            AddressClass.ipBytes(InetSocketAddress("fe80::1%en0", 1)),
        )
        assertTrue(AddressClass.isLoopback(InetSocketAddress("0:0:0:0:0:0:0:1", 1)))
    }

    @Test fun malformedLiteralsAreNotAddresses() {
        for (s in listOf("1.2.3", "1.2.3.256", "1.2.3.4.5", "01.2.3.4x", "1:2:3:4:5:6:7:8:9", "1::2::3", ":1", "12345::", "g::1", "")) {
            assertContentEquals(s.encodeToByteArray(), AddressClass.ipBytes(InetSocketAddress(s, 1)), s)
        }
    }

    @Test fun nonAsciiDigitsAndLeadingZerosAreNotAddresses() {
        // only ASCII hex digits; an octet with a leading zero is ambiguous (inet_aton reads 010 as octal 8), so not an address
        for (s in listOf("fe80::\u0661", "fe80::\uFF46", "\u0661.2.3.4", "010.0.0.1", "1.2.3.00", "::ffff:010.0.0.1")) {
            assertContentEquals(s.encodeToByteArray(), AddressClass.ipBytes(InetSocketAddress(s, 1)), s)
        }
        assertContentEquals(bytes(0, 0, 0, 0), AddressClass.ipBytes(InetSocketAddress("0.0.0.0", 1)))
        assertContentEquals(bytes(10, 0, 0, 1), AddressClass.ipBytes(InetSocketAddress("10.0.0.1", 1)))
    }
}
