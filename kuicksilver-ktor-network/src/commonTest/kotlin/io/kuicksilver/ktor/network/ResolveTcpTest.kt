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
        assertNull(parseIpv4Literal("010.0.0.1")) // octal to inet_aton: left to the platform
        assertNull(parseIpv4Literal("1.2.3.00"))
        assertContentEquals(byteArrayOf(0, 0, 0, 0), parseIpv4Literal("0.0.0.0"))
    }

    /** An invalid IPv6 literal fails at once instead of being handed to the system resolver as a name. */
    @Test fun negative_invalidIpv6LiteralIsNotLookedUp() =
        runBlocking<Unit> {
            blockingLookupForTest = { name, _ -> error("looked up: $name") }
            try {
                assertFailsWith<IOException> { resolveTcp("[::zz]", 80) }
                assertFailsWith<IOException> { resolveTcp("g::1", 80) }
            } finally {
                blockingLookupForTest = null
            }
        }

    /**
     * A resolver that stalls holds at most [MAX_CONCURRENT_LOOKUPS] threads however many requests wait for it, the other
     * threads of `Dispatchers.IO` (the socket loops') keep running, and one lookup per name and family is in flight: 40
     * callers of 20 stalled names make 40 lookups (AAAA and A), 8 of each family running.
     */
    @Test fun negative_stalledResolverHoldsBoundedThreads() =
        runBlocking<Unit> {
            val gate = CompletableDeferred<Unit>()
            val boundReached = CompletableDeferred<Unit>()
            val inside = AtomicInt(0)
            val maxInside = AtomicInt(0)
            val calls = AtomicInt(0)
            blockingLookupForTest = { _, ipv6 ->
                calls.addAndFetch(1)
                val now = inside.addAndFetch(1)
                while (true) {
                    val m = maxInside.load()
                    if (now <= m || maxInside.compareAndSet(m, now)) break
                }
                if (now == 2 * MAX_CONCURRENT_LOOKUPS) boundReached.complete(Unit)
                runBlocking { gate.await() } // a blocked system call: the thread is held until the gate opens
                inside.addAndFetch(-1)
                if (ipv6) emptyList() else listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), 0))
            }
            try {
                // undispatched: each caller has joined its name's lookup when async returns
                val callers =
                    (0 until 40).map { i ->
                        async(start = CoroutineStart.UNDISPATCHED) { resolveTcp("stalled-${i % 20}.test", 443) }
                    }
                assertEquals(40, lookupsInFlightForTest()) // a lookup per name and family
                withTimeout(10.seconds) { boundReached.await() }
                // the socket loops' dispatcher still has threads
                assertEquals(42, withTimeout(5.seconds) { withContext(Dispatchers.IO) { 42 } })
                assertEquals(2 * MAX_CONCURRENT_LOOKUPS, inside.load()) // 8 per family
                gate.complete(Unit)
                val results = withTimeout(10.seconds) { callers.awaitAll() }
                results.forEach { assertEquals(listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), 443)), it) }
                assertEquals(40, calls.load(), "one lookup per name and family")
                assertEquals(2 * MAX_CONCURRENT_LOOKUPS, maxInside.load())
                assertEquals(0, lookupsInFlightForTest())
            } finally {
                gate.complete(Unit)
                blockingLookupForTest = null
            }
        }

    /**
     * Each family has its own budget: on a network that drops AAAA queries, a storm of stalled IPv6 lookups does not hold
     * up the IPv4 lookup of another name.
     */
    @Test fun negative_stalledAaaaLookupsDoNotBlockALookupsOfOtherNames() =
        runBlocking<Unit> {
            val gate = CompletableDeferred<Unit>()
            blockingLookupForTest = { name, ipv6 ->
                if (ipv6) runBlocking { gate.await() }
                if (ipv6) emptyList() else listOf(TcpAddress(byteArrayOf(127, 0, 0, if (name == "other.test") 2 else 1), 0))
            }
            try {
                val stalled =
                    (0 until 20).map { i ->
                        async(start = CoroutineStart.UNDISPATCHED) { resolveFamily("stalled-$i.test", true) }
                    }
                val a = withTimeout(10.seconds) { resolveFamily("other.test", false) }
                assertEquals(listOf(TcpAddress(byteArrayOf(127, 0, 0, 2), 0)), a)
                gate.complete(Unit)
                withTimeout(10.seconds) { stalled.awaitAll() }
            } finally {
                gate.complete(Unit)
                blockingLookupForTest = null
            }
        }

    /** Answers are kept for the platform's TTLs (the JDK's `networkaddress.cache.ttl`), positive and negative alike. */
    @Test fun answersAreKeptForTheirTtl() =
        runBlocking<Unit> {
            var calls = 0
            blockingLookupForTest = { name, _ ->
                calls++
                if (name == "none.test") throw IOException("NXDOMAIN") else listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), 0))
            }
            try {
                cacheTtlForTest = LookupTtl(30, 10)
                clearLookupCacheForTest()
                repeat(3) { resolveFamily("kept.test", false) }
                repeat(3) { assertFailsWith<IOException> { resolveFamily("none.test", false) } }
                assertEquals(2, calls)
                cacheTtlForTest = LookupTtl(0, 0)
                clearLookupCacheForTest()
                repeat(2) { resolveFamily("kept.test", false) }
                assertEquals(4, calls)
            } finally {
                cacheTtlForTest = null
                clearLookupCacheForTest()
                blockingLookupForTest = null
            }
        }
}
