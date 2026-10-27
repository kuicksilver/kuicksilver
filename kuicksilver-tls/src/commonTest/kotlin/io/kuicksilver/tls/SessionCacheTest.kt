// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
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

    /**
     * Soak regression (0.2.0, `ksl.session` left at 1): put owns the entry it is given. A TLS reader cancelled while it waited
     * for the cache's lock (its connection closed) dropped the entry, and with it a native session nothing would ever free.
     */
    @Test fun putCancelledWhileWaitingReleasesEntry(): Unit =
        runBlocking {
            val cache = SessionCache()
            val e = SessionCache.Entry(0L, emptyList(), emptyList())
            cache.mutex.lock()
            val putter = launch(start = CoroutineStart.UNDISPATCHED) { cache.put("k", e) }
            putter.cancel()
            cache.mutex.unlock()
            putter.join()
            assertTrue(e.closed || cache.peek("k"), "the entry is either cached or released, never lost")
            cache.clear()
            assertTrue(e.closed)
        }

    /** A cache that was closed (its engine or endpoint is gone) releases what is stored afterwards instead of keeping it. */
    @Test fun putAfterCloseReleasesEntry(): Unit =
        runBlocking {
            val cache = SessionCache()
            cache.close()
            val e = SessionCache.Entry(0L, emptyList(), emptyList())
            cache.put("k", e)
            assertTrue(e.closed, "released at once")
            assertEquals(0, cache.size())
        }

    /**
     * RFC 9846 appendix C.4: a server "SHOULD offer at least as many tickets as the number of connections that a client might
     * use"; the cache keeps a few tickets per origin (the newest first, each used once), so parallel HTTP/1.1 connections each
     * resume. A QUIC origin keeps one: its transport stores every ticket, and 0-RTT needs only the newest.
     */
    @Test fun severalTicketsPerOrigin(): Unit =
        runBlocking {
            val cache = SessionCache()
            val es = List(5) { SessionCache.Entry(0L, emptyList(), emptyList()) }
            es.forEach { cache.put("k", it) }
            assertEquals(4, cache.size(), "four tickets per origin")
            assertTrue(es[0].closed && !es[1].closed, "the oldest beyond four is released")
            assertTrue(cache.take("k") === es[4] && cache.take("k") === es[3], "the newest first, each once")
            assertEquals(2, cache.size())
            val cfg = Fixtures.client()
            val q1 = QuicSessionTicket(SessionCache.Entry(0L, emptyList(), emptyList()))
            cache.putQuic(cfg, q1)
            cache.putQuic(cfg, QuicSessionTicket(SessionCache.Entry(0L, emptyList(), emptyList())))
            assertTrue(q1.entry.closed && cache.size() == 3, "a QUIC origin keeps only its newest ticket")
        }

    /** A QUIC ticket is taken once (RFC 8446 appendix C.4) and only while its cached chain still passes the current trust. */
    @Test fun clientTicketIsSingleUse(): Unit =
        runBlocking {
            val cache = SessionCache()
            val cfg = Fixtures.client()
            cache.putQuic(cfg, QuicSessionTicket(SessionCache.Entry(0L, emptyList(), emptyList())).also { it.remembered = byteArrayOf(7) })
            val t = cache.takeQuic(cfg)
            assertTrue(t != null && t.remembered!!.contentEquals(byteArrayOf(7)), "the ticket and what the transport remembered")
            assertEquals(null, cache.takeQuic(cfg), "single use")
            val rejecting = Fixtures.client(trust = TrustConfig.Custom { _, _, _ -> VerifyResult.Rejected(VerifyReason.Custom("no")) })
            val e = SessionCache.Entry(0L, listOf(Fixtures.testCa), emptyList())
            cache.putQuic(rejecting, QuicSessionTicket(e))
            assertEquals(null, cache.takeQuic(rejecting), "a chain the trust now rejects is not resumed")
            assertTrue(e.closed)
        }
}
