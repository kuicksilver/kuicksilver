// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** [loopbackLocalFor]: a loopback peer is reached from the loopback address of its family, any other peer is not. */
class LoopbackLocalTest {
    @Test fun loopbackPeersGetTheLoopbackOfTheirFamily() {
        assertEquals("127.0.0.1", loopbackLocalFor(InetSocketAddress("127.0.0.1", 443))?.ipLiteral())
        assertEquals("127.0.0.1", loopbackLocalFor(InetSocketAddress("127.9.8.7", 443))?.ipLiteral())
        assertEquals("::1", loopbackLocalFor(InetSocketAddress("::1", 443))?.ipLiteral())
        assertEquals(0, loopbackLocalFor(InetSocketAddress("::1", 443))?.port)
    }

    /** Not loopback: ::2, 128.0.0.1, the wildcard addresses, public addresses. */
    @Test fun negative_lookalikesAreNoLoopback() {
        for (a in listOf("::2", "128.0.0.1", "0.0.0.0", "::", "192.0.2.1", "2001:db8::1")) {
            assertNull(loopbackLocalFor(InetSocketAddress(a, 443)), a)
        }
    }
}
