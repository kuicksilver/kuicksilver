// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.interop

import io.ktor.network.sockets.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals

/** [clientLocalAddress]: a loopback server from the loopback of its family, any other from the wildcard address. */
class ClientLocalTest {
    private fun ip(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    @Test fun loopbackServersAreReachedFromLoopback() {
        assertEquals(InetSocketAddress("127.0.0.1", 0), clientLocalAddress(ip(127, 0, 0, 1)))
        assertEquals(InetSocketAddress("127.0.0.1", 0), clientLocalAddress(ip(127, 1, 2, 3)))
        assertEquals(InetSocketAddress("::1", 0), clientLocalAddress(ip(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)))
    }

    @Test fun otherServersAreReachedFromTheWildcardOfTheirFamily() {
        assertEquals(InetSocketAddress("0.0.0.0", 0), clientLocalAddress(ip(193, 167, 0, 100)))
        assertEquals(InetSocketAddress("::", 0), clientLocalAddress(ip(0xfd, 0, 0, 0xd0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64)))
    }

    /** Not loopback: ::ffff:127.0.0.1 is a v4-mapped address, ::2 and 128.0.0.1 are no loopback, an unresolved name is none. */
    @Test fun negative_lookalikesAreNotLoopback() {
        assertEquals(InetSocketAddress("::", 0), clientLocalAddress(ip(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1)))
        assertEquals(InetSocketAddress("::", 0), clientLocalAddress(ip(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)))
        assertEquals(InetSocketAddress("0.0.0.0", 0), clientLocalAddress(ip(128, 0, 0, 1)))
        assertEquals(InetSocketAddress("0.0.0.0", 0), clientLocalAddress(null))
    }
}
