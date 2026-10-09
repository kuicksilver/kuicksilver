// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.native.KslLoader
import java.util.Collections
import java.util.concurrent.CountDownLatch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Every endpoint loop draws randomness at the same time; the process-wide source must neither repeat bytes nor overrun its buffer. */
class KslRandomConcurrencyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun hammer(
        threads: Int,
        perThread: Int,
        draw: (Int) -> ByteArray,
    ): Pair<List<Throwable>, Set<String>> {
        val errors = Collections.synchronizedList(ArrayList<Throwable>())
        val seen =
            Collections.synchronizedSet(
                HashSet<String>(threads * perThread * 2),
            )
        val start = CountDownLatch(1)
        val workers =
            List(threads) { t ->
                Thread {
                    start.await()
                    try {
                        repeat(perThread) {
                            val b = draw(t)
                            seen +=
                                b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
                        }
                    } catch (e: Throwable) {
                        errors += e
                    }
                }
            }
        workers.forEach { it.start() }
        start.countDown()
        workers.forEach { it.join() }
        return errors to seen
    }

    @Test fun sharedSourceIsThreadSafe() {
        val (errors, seen) = hammer(4, 10_000) { KslRandom.nextBytes(ByteArray(32)) }
        assertTrue(errors.isEmpty(), "no exception: ${errors.firstOrNull()}")
        assertEquals(40_000, seen.size, "no two draws returned the same 32 bytes")
    }

    @Test fun perLoopSourcesAreIndependent() {
        val sources = List(4) { KslRandom.newSource() }
        val (errors, seen) = hammer(4, 10_000) { t -> sources[t].nextBytes(ByteArray(32)) }
        assertTrue(errors.isEmpty(), "no exception: ${errors.firstOrNull()}")
        assertEquals(40_000, seen.size, "no two draws returned the same 32 bytes")
    }
}
