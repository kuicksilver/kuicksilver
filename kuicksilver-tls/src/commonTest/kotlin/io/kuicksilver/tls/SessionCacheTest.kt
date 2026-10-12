// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The client session cache does not keep expired sessions until someone asks for exactly their key. */
class SessionCacheTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    /** The cache is bounded: the 257th session evicts the least recently stored one, whose native session is freed. */
    @Test fun capEvictsOldestAndFreesNative(): Unit =
        runBlocking {
            val cache = SessionCache(maxEntries = 256)
            val first = SessionCache.Entry(0L, emptyList(), emptyList())
            cache.put("k0", first)
            for (i in 1..256) cache.put("k$i", SessionCache.Entry(0L, emptyList(), emptyList()))
            assertEquals(256, cache.size())
            assertTrue(!cache.peek("k0") && cache.peek("k1") && cache.peek("k256"), "the oldest entry went first")
            assertTrue(first.closed, "the evicted entry released its native session")
            cache.clear()
            assertEquals(0, cache.size())
        }

    /** Two caches are independent: a session stored in one is not visible through the other (one cache per engine). */
    @Test fun cachesAreIndependent(): Unit =
        runBlocking {
            val a = SessionCache()
            val b = SessionCache()
            a.put("k", SessionCache.Entry(0L, emptyList(), emptyList()))
            assertTrue(a.peek("k") && !b.peek("k") && !SessionCache.Default.peek("k"))
            a.clear()
        }

    @Test fun expiredEntriesPurgedOnPut(): Unit =
        runBlocking {
            val old = nowSeconds() - 8L * 24 * 3600
            SessionCache.Default.put("a", SessionCache.Entry(0L, emptyList(), emptyList(), created = old))
            SessionCache.Default.put("b", SessionCache.Entry(0L, emptyList(), emptyList(), created = old))
            SessionCache.Default.put("c", SessionCache.Entry(0L, emptyList(), emptyList()))
            assertEquals(1, SessionCache.Default.size(), "the two week-old sessions are gone once a fresh one is stored")
            assertTrue(SessionCache.Default.peek("c"))
            SessionCache.Default.clear()
        }
}
