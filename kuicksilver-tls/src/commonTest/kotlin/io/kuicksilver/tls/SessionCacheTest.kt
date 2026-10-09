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
        runBlocking { SessionCache.clear() }
    }

    @Test fun expiredEntriesPurgedOnPut(): Unit =
        runBlocking {
            val old = nowSeconds() - 8L * 24 * 3600
            SessionCache.put("a", SessionCache.Entry(0L, emptyList(), emptyList(), created = old))
            SessionCache.put("b", SessionCache.Entry(0L, emptyList(), emptyList(), created = old))
            SessionCache.put("c", SessionCache.Entry(0L, emptyList(), emptyList()))
            assertEquals(1, SessionCache.size(), "the two week-old sessions are gone once a fresh one is stored")
            assertTrue(SessionCache.peek("c"))
            SessionCache.clear()
        }
}
