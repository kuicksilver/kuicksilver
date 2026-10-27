// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AltSvcTest {
    private var now = 1_000_000L
    private val store = InMemoryAltSvcStore()
    private val cache = AltSvcCache(store) { now }
    private val origin = Url("https://example.com/")

    private fun respond(
        status: Int = 200,
        vararg values: String,
        verified: Boolean = true,
        url: Url = origin,
    ) = cache.onResponse(url, status, values.toList(), verified)

    @Test fun parsesMaAndPersist() {
        val e = AltSvcParser.parse("h3=\":443\"; ma=3600; persist=1, h3-29=\":443\"", now)!!
        assertEquals(1, e.size)
        assertEquals("h3", e[0].protocol)
        assertNull(e[0].host)
        assertEquals(443, e[0].port)
        assertEquals(now + 3_600_000, e[0].expiresAtEpochMillis)
        assertTrue(e[0].persist)
    }

    /** One header with 100 alternatives keeps the first `MAX_ENTRIES_PER_ORIGIN` (as Chromium): the store is bounded per origin. */
    @Test fun negative_altSvcEntriesPerOriginCapped() {
        respond(200, (1..100).joinToString(", ") { "h3=\":$it\"" })
        assertEquals(AltSvcCache.MAX_ENTRIES_PER_ORIGIN, store.get(cache.originOf(origin)).size)
        assertEquals(1, cache.h3For(origin)?.port)
    }

    /**
     * `ma` is delta-seconds (RFC 7838 section 3.1): a value too large to represent is taken as 2147483648 (RFC 9111 section
     * 1.2.2 MUST), not dropped; before, `ma=99999999999999999999` skipped the alternative. A sign is no delta-seconds.
     */
    @Test fun overflowingMaIsCapped() {
        for (ma in listOf("99999999999999999999", "\"99999999999999999999\"")) {
            val e = AltSvcParser.parse("h3=\":443\"; ma=$ma", now)!!
            assertEquals(listOf(now + 2_147_483_648_000L), e.map { it.expiresAtEpochMillis }, ma)
        }
        assertEquals(now + 2_147_483_649_000L, AltSvcParser.parse("h3=\":443\"; ma=2147483649", now)!!.single().expiresAtEpochMillis)
        assertEquals(emptyList(), AltSvcParser.parse("h3=\":443\"; ma=+5", now))
    }

    @Test fun defaultMa86400() {
        assertEquals(now + 86_400_000, AltSvcParser.parse("h3=\"alt.example.com:8443\"", now)!!.single().expiresAtEpochMillis)
    }

    @Test fun clearReturnsNull() {
        assertNull(AltSvcParser.parse("clear", now))
    }

    @Test fun malformedEntriesSkipped() {
        assertEquals(
            listOf(443),
            AltSvcParser.parse("h3=:443, h3=\"x:notaport\", h3=\":444\"; ma=abc, h3=\":443\"; ma=60", now)!!.map { it.port },
        )
    }

    @Test fun replacesAllEntriesOfOrigin() {
        respond(200, "h3=\":443\"")
        respond(200, "h3=\"alt.example.com:443\"; ma=60")
        assertEquals("alt.example.com", cache.h3For(origin)!!.host)
        assertEquals(1, store.get("https://example.com:443").size)
        respond(200, "clear")
        assertNull(cache.h3For(origin))
    }

    /** A 421 is not authoritative for the origin (RFC 9110 section 15.5.20): neither its `Alt-Svc` nor its status changes the cache. */
    @Test fun status421LeavesEntries() {
        respond(200, "h3=\":443\"")
        respond(421, "h3=\":9443\"")
        assertEquals(443, cache.h3For(origin)?.port)
        respond(421, "clear")
        assertEquals(443, cache.h3For(origin)?.port)
    }

    /** RFC 7838 section 6: a 421 from an alternative removes that entry of the origin's cache, not the others. */
    @Test fun removeAlternativeKeepsTheOthers() {
        respond(200, "h3=\":443\", h3=\"alt.example.com:443\"")
        cache.removeAlternative(origin, cache.h3For(origin)!!)
        assertEquals("alt.example.com", cache.h3For(origin)?.host)
        cache.removeAlternative(origin, cache.h3For(origin)!!)
        assertNull(cache.h3For(origin))
        assertTrue(store.get(cache.originOf(origin)).isEmpty())
    }

    @Test fun lowPortOriginRejectsHighAltPort() {
        respond(200, "h3=\":8443\"")
        assertNull(cache.h3For(origin)) // origin 443 (privileged) -> alt 8443 refused
        val high = Url("https://example.com:8443/")
        respond(200, "h3=\":9443\"", url = high)
        assertEquals(9443, cache.h3For(high)!!.port) // origin 8443 -> alt 9443 accepted
    }

    @Test fun expiredEntryIgnored() {
        respond(200, "h3=\":443\"; ma=10")
        now += 11_000
        assertNull(cache.h3For(origin))
    }

    @Test fun negative_altSvcFromUnverifiedTls() {
        respond(200, "h3=\":443\"", verified = false)
        assertNull(cache.h3For(origin))
        assertTrue(store.get("https://example.com:443").isEmpty())
    }

    @Test fun networkChangeClearsNonPersistent() {
        respond(200, "h3=\":443\"")
        respond(200, "h3=\":443\"; persist=1", url = Url("https://other.example/"))
        cache.onNetworkChanged(clearNonPersistent = true)
        assertNull(cache.h3For(origin))
        assertNotNull(cache.h3For(Url("https://other.example/")))
    }

    /**
     * Quoted strings are processed as RFC 9110 section 5.6.4 says (RFC 7838 section 3): a quoted-pair stands for its
     * character, so an escaped quote neither ends the string nor lets a comma inside it split the list.
     */
    @Test fun quotedPairsAreProcessed() {
        assertEquals(listOf(443, 8443), AltSvcParser.parse("h3=\":443\"; foo=\"a\\\",b\", h3=\":8443\"", now)!!.map { it.port })
        assertEquals("alt.example.com", AltSvcParser.parse("h3=\"alt.exam\\ple.com:8443\"", now)!!.single().host)
        assertEquals(listOf(8443), AltSvcParser.parse("h3=\":443\\\"\", h3=\":8443\"", now)!!.map { it.port })
    }
}
