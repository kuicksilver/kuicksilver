// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** [SharedPerKey]: one upstream registration per key however many collectors (one default-network callback per ConnectivityManager). */
class SharedPerKeyTest {
    /** A fake callback registration per key: counts registrations and unregistrations; [value] is what it reports. */
    private class Fake {
        val registered = AtomicInteger()
        val unregistered = AtomicInteger()
        val value = MutableStateFlow(1)

        fun upstream(key: String): Flow<Int> =
            callbackFlow {
                registered.incrementAndGet()
                val j = launch { value.collect { send(it) } }
                awaitClose {
                    j.cancel()
                    unregistered.incrementAndGet()
                }
            }
    }

    @Test fun manyCollectorsShareOneRegistration() =
        runBlocking {
            withTimeout(30.seconds) {
                val fake = Fake()
                val shared = SharedPerKey<String, Int>(fake::upstream)
                coroutineScope {
                    val seen = List(10) { CompletableDeferred<List<Int>>() }
                    val collectors =
                        List(10) { i ->
                            launch { seen[i].complete(shared["cm"].take(2).toList()) }
                        }
                    // each collector got the current value; one more change reaches all of them
                    while (fake.registered.get() == 0) kotlinx.coroutines.yield()
                    shared["cm"].first()
                    fake.value.value = 2
                    collectors.forEach { it.join() }
                    seen.forEach { assertEquals(listOf(1, 2), it.await()) }
                }
                assertEquals(1, fake.registered.get(), "one registration for ten collectors")
                withTimeout(10.seconds) { while (fake.unregistered.get() != 1) kotlinx.coroutines.yield() }
                // the last collector left: the next one registers again (the manager is not kept)
                assertEquals(2, shared["cm"].first())
                assertEquals(2, fake.registered.get())
                shared["other"].first()
                assertEquals(3, fake.registered.get(), "a registration per key")
            }
        }

    @Test fun anUpstreamFailureReachesTheCollectorsAndIsNotCached() =
        runBlocking {
            withTimeout(30.seconds) {
                var calls = 0
                val shared =
                    SharedPerKey<String, Int> {
                        flow {
                            if (++calls == 1) throw IllegalStateException("too many requests")
                            emit(7)
                            awaitCancellation()
                        }
                    }
                assertEquals("too many requests", assertFailsWith<IllegalStateException> { shared["cm"].first() }.message)
                assertEquals(7, shared["cm"].first(), "a later collector registers anew")
            }
        }
}
