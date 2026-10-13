// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlin.test.Test
import kotlin.test.assertEquals

/** The address text of the native sockets' `localAddress`/`remoteAddress` (RFC 5952 for IPv6). */
class IpTextTest {
    private fun v6(vararg groups: Int): ByteArray =
        ByteArray(16).also { b ->
            groups.forEachIndexed { i, g ->
                b[2 * i] = (g shr 8).toByte()
                b[2 * i + 1] = g.toByte()
            }
        }

    @Test fun ipv4() = assertEquals("127.0.0.1", ipText(byteArrayOf(127, 0, 0, 1)))

    @Test fun ipv4HighOctets() = assertEquals("255.200.0.10", ipText(byteArrayOf(-1, -56, 0, 10)))

    @Test fun loopbackAndAny() {
        assertEquals("::1", ipText(v6(0, 0, 0, 0, 0, 0, 0, 1)))
        assertEquals("::", ipText(ByteArray(16)))
    }

    @Test fun longestZeroRunIsCompressedFirstOnATie() {
        assertEquals("2001:db8::1:0:0:1", ipText(v6(0x2001, 0xdb8, 0, 0, 1, 0, 0, 1)))
        assertEquals("2001:0:0:1::1", ipText(v6(0x2001, 0, 0, 1, 0, 0, 0, 1)))
    }

    @Test fun singleZeroGroupIsNotCompressed() = assertEquals("2001:db8:0:1:1:1:1:1", ipText(v6(0x2001, 0xdb8, 0, 1, 1, 1, 1, 1)))

    @Test fun lowerCaseWithoutLeadingZeros() = assertEquals("fe80::abcd:ef", ipText(v6(0xfe80, 0, 0, 0, 0, 0, 0xabcd, 0xef)))

    @Test fun trailingRun() = assertEquals("fe80::", ipText(v6(0xfe80)))

    @Test fun ipv4MappedAsInetNtopWritesIt() = assertEquals("::ffff:192.0.2.1", ipText(v6(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201)))
}
