// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.endpoint.EndpointPair
import java.util.concurrent.Executors
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith

/**
 * The fixtures count PacketBuffers per thread: one closed on another thread than the one that built it fails its close
 * and says why, instead of comparing the counts of two threads (a false leak, or a leak hidden).
 */
class FixtureThreadTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun <T> onAnotherThread(block: () -> T): T {
        val pool = Executors.newSingleThreadExecutor()
        try {
            return pool.submit<T> { block() }.get()
        } finally {
            pool.shutdown()
        }
    }

    @Test fun negative_aCorePairClosedOnAnotherThreadSaysSo() {
        val p = CorePair()
        val e = assertFailsWith<java.util.concurrent.ExecutionException> { onAnotherThread { p.close() } }
        assertContains(e.cause?.message.orEmpty(), "closed on another thread than the one that built it")
    }

    @Test fun negative_anEndpointPairClosedOnAnotherThreadSaysSo() {
        val p = EndpointPair()
        val e = assertFailsWith<java.util.concurrent.ExecutionException> { onAnotherThread { p.close() } }
        assertContains(e.cause?.message.orEmpty(), "closed on another thread than the one that built it")
    }
}
