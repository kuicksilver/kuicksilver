// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import java.lang.management.ManagementFactory
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * What one whole QUIC connection (handshake with ksl crypto, close, both cores closed; [CoreHandshakes]) allocates on the JVM
 * heap, client and server together on this thread: a ceiling, so per-connection buffers made up front do not creep back (P.3:
 * lazy CRYPTO send rings and receive scratch). Native memory (OpenSSL) is not counted here.
 */
class HandshakeAllocationTest {
    private val mx = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean

    @Test fun aConnectionStaysUnderItsAllocationCeiling() {
        CoreHandshakes().use { h ->
            repeat(300) { assertTrue(h.connection(), "connection") } // warm-up: classes load, the JIT settles
            val n = 500
            val before = mx.currentThreadAllocatedBytes
            repeat(n) { assertTrue(h.connection(), "connection") }
            val perConnection = (mx.currentThreadAllocatedBytes - before) / n
            println("handshake allocation: $perConnection bytes per connection (client and server)")
            assertTrue(perConnection <= CEILING, "a connection allocated $perConnection bytes (ceiling $CEILING); find the sites with JFR")
        }
    }

    private companion object {
        const val CEILING = 125_000L // 112 652 measured (2026-11-05, JVM 21); 169 542 before the lazy CRYPTO buffers
    }
}
