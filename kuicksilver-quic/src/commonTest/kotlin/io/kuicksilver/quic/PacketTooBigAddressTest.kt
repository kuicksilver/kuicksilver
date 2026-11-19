// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The addresses a CONNECT-UDP proxy's Packet Too Big leaves from and goes to (RFC 9298 section 6.1): an IPv4-mapped IPv6
 * address, which Kotlin/Native keeps as 16 bytes, is IPv4 to the raw socket, so an IPv4 target and a dual-stack proxy
 * socket meet in one family; a wildcard in any spelling names no source.
 */
class PacketTooBigAddressTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun anIpv4MappedAddressIsEncodedAsIpv4() {
        val e = PacketTooBigSender.encode(InetSocketAddress("::ffff:10.0.0.2", 4433))!!
        assertEquals(4, e[0].toInt(), "family")
        assertEquals(4433, ((e[1].toInt() and 0xff) shl 8) or (e[2].toInt() and 0xff))
        assertContentEquals(byteArrayOf(10, 0, 0, 2), e.copyOfRange(3, 7))
        assertContentEquals(e, PacketTooBigSender.encode(InetSocketAddress("10.0.0.2", 4433)))
        assertEquals(6, PacketTooBigSender.encode(InetSocketAddress("2001:db8::1", 4433))!![0].toInt())
    }

    @Test fun specificIpOrNull() {
        for (w in listOf("0.0.0.0", "::", "::%1", "::ffff:0.0.0.0", "0:0:0:0:0:0:0:0")) {
            assertNull(InetSocketAddress(w, 4433).specificIpOrNull(), w)
        }
        assertNull(InetSocketAddress("10.0.0.2", 0).specificIpOrNull(), "port 0")
        assertEquals("10.0.0.2", InetSocketAddress("::ffff:10.0.0.2", 4433).specificIpOrNull()?.ipLiteral())
        assertEquals("2001:db8::1", InetSocketAddress("2001:db8::1", 4433).specificIpOrNull()?.ipLiteral())
        assertEquals(4433, InetSocketAddress("::ffff:10.0.0.2", 4433).withUnmappedIp().port)
    }
}
