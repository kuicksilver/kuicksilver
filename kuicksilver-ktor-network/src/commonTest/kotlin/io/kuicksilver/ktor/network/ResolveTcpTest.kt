// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.network

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/** [resolveTcp]: literals never reach the resolver; name lookups are bounded and shared (threat model 3.21). */
class ResolveTcpTest {
    @Test fun ipv4LiteralsAreStrict() {
        assertContentEquals(byteArrayOf(10, 0, -1, 1), parseIpv4Literal("10.0.255.1"))
        assertNull(parseIpv4Literal("999.1.1.1"))
        assertNull(parseIpv4Literal("1.2.3"))
        assertNull(parseIpv4Literal("1.2.3.4.5"))
        assertNull(parseIpv4Literal("1.2.3.0004"))
        assertNull(parseIpv4Literal("1.2.+3.4"))
    }

    /** An invalid IPv6 literal fails at once instead of being handed to the system resolver as a name. */
    @Test fun negative_invalidIpv6LiteralIsNotLookedUp() =
        runBlocking<Unit> {
            blockingLookupForTest = { error("looked up: $it") }
            try {
                assertFailsWith<IOException> { resolveTcp("[::zz]", 80) }
                assertFailsWith<IOException> { resolveTcp("g::1", 80) }
            } finally {
                blockingLookupForTest = null
            }
        }

    /**
     * A resolver that stalls holds at most [MAX_CONCURRENT_LOOKUPS] threads however many requests wait for it, the other
     * threads of `Dispatchers.IO` (the socket loops') keep running, and one lookup per name is in flight: 40 callers of
     * 20 stalled names make 20 lookups, 8 of them running.
     */
    @Test fun negative_stalledResolverHoldsBoundedThreads() =
        runBlocking<Unit> {
            val gate = CompletableDeferred<Unit>()
            val boundReached = CompletableDeferred<Unit>()
            val inside = AtomicInt(0)
            val maxInside = AtomicInt(0)
            val calls = AtomicInt(0)
            blockingLookupForTest = { _ ->
                calls.addAndFetch(1)
                val now = inside.addAndFetch(1)
                while (true) {
                    val m = maxInside.load()
                    if (now <= m || maxInside.compareAndSet(m, now)) break
                }
                if (now == MAX_CONCURRENT_LOOKUPS) boundReached.complete(Unit)
                runBlocking { gate.await() } // a blocked system call: the thread is held until the gate opens
                inside.addAndFetch(-1)
                listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), 0))
            }
            try {
                // undispatched: each caller has joined its name's lookup when async returns
                val callers =
                    (0 until 40).map { i ->
                        async(start = CoroutineStart.UNDISPATCHED) { resolveTcp("stalled-${i % 20}.test", 443) }
                    }
                assertEquals(20, lookupsInFlightForTest())
                withTimeout(10.seconds) { boundReached.await() }
                // the socket loops' dispatcher still has threads
                assertEquals(42, withTimeout(5.seconds) { withContext(Dispatchers.IO) { 42 } })
                assertEquals(MAX_CONCURRENT_LOOKUPS, inside.load())
                gate.complete(Unit)
                val results = withTimeout(10.seconds) { callers.awaitAll() }
                results.forEach { assertEquals(listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), 443)), it) }
                assertEquals(20, calls.load(), "one lookup per name")
                assertEquals(MAX_CONCURRENT_LOOKUPS, maxInside.load())
                assertEquals(0, lookupsInFlightForTest())
            } finally {
                gate.complete(Unit)
                blockingLookupForTest = null
            }
        }
}
