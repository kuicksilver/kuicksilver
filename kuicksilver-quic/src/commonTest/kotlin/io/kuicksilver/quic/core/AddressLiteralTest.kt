// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.ipLiteral
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

    @Test fun withLiteralHostKeepsThePortAndResolvesToTheSameBytes() {
        val a = InetSocketAddress("0.0.0.0", 4433).withLiteralHost(5555)
        assertEquals(5555, a.port)
        assertEquals("0.0.0.0", a.ipLiteral())
        assertEquals(InetSocketAddress("0.0.0.0", 5555), a)
    }
}
