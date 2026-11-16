// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * [loopbackLocalFor]: a peer written as a loopback IP literal is reached from the loopback address of the family its
 * traffic uses, any other peer is not; the same on every platform (the JVM turns an IPv4-mapped literal into an IPv4
 * address and resolves names when the address is made, Kotlin/Native does neither).
 */
class LoopbackLocalTest {
    @Test fun loopbackPeersGetTheLoopbackOfTheirFamily() {
        assertEquals("127.0.0.1", loopbackLocalFor(InetSocketAddress("127.0.0.1", 443))?.ipLiteral())
        assertEquals("127.0.0.1", loopbackLocalFor(InetSocketAddress("127.9.8.7", 443))?.ipLiteral())
        assertEquals("::1", loopbackLocalFor(InetSocketAddress("::1", 443))?.ipLiteral())
        assertEquals(0, loopbackLocalFor(InetSocketAddress("::1", 443))?.port)
    }

    /** An IPv4-mapped loopback address is IPv4 loopback traffic: the IPv4 loopback, and the peer sent to as IPv4. */
    @Test fun anIpv4MappedLoopbackIsIpv4Loopback() {
        for (a in listOf("::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:127.1.2.3")) {
            assertEquals("127.0.0.1", loopbackLocalFor(InetSocketAddress(a, 443))?.ipLiteral(), a)
        }
        assertEquals("127.0.0.1", InetSocketAddress("::ffff:7f00:1", 443).unmappedLiteral().ipLiteral())
        assertEquals(443, InetSocketAddress("::ffff:7f00:1", 443).unmappedLiteral().port)
        assertEquals("::1", InetSocketAddress("::1", 443).unmappedLiteral().ipLiteral(), "not mapped: as it is")
    }

    /** Not loopback: ::2, 128.0.0.1, an IPv4-mapped 128.0.0.1, the wildcard addresses, public addresses, and a name. */
    @Test fun negative_lookalikesAreNoLoopback() {
        for (a in listOf("::2", "128.0.0.1", "::ffff:128.0.0.1", "0.0.0.0", "::", "192.0.2.1", "2001:db8::1")) {
            assertNull(loopbackLocalFor(InetSocketAddress(a, 443)), a)
        }
        // a name stays a name, on the JVM too (where it was resolved when the address was made): no lookup decides it
        assertNull(loopbackLocalFor(InetSocketAddress("localhost", 443)), "localhost")
    }
}
