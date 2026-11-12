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
        age: List<String> = emptyList(),
        delayMillis: Long = 0,
    ) = cache.onResponse(url, status, values.toList(), verified, age, delayMillis)

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
     * `ma` is delta-seconds (RFC 7838 section 3.1): a value too large to represent is taken as 2147483648, as RFC 9111
     * section 1.2.2 says a cache MUST, not dropped; before, `ma=99999999999999999999` skipped the alternative. A sign is
     * no delta-seconds.
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

    /**
     * RFC 7838 section 3: "A field value containing the special value "clear" indicates that the origin requests all
     * alternatives for that origin to be invalidated (including those specified in the same response, in case of an invalid
     * reply containing both "clear" and alternative services)." Before, only a value that was `clear` as a whole cleared, and
     * `clear, h3=":443"` (two field lines an intermediary folded, or a stale value appended) stored the alternative.
     */
    @Test fun negative_clearAmongAlternativesInvalidatesThemAll() {
        for (value in listOf("clear, h3=\":443\"", "h3=\":443\", clear", "h3=\":443\" ,  clear  , h3=\":8443\"")) {
            assertNull(AltSvcParser.parse(value, now), value)
            respond(200, "h3=\":443\"")
            respond(200, value)
            assertNull(cache.h3For(origin), value)
            assertTrue(store.get(cache.originOf(origin)).isEmpty(), value)
        }
        // "clear" is case-sensitive and a whole list element: neither of these is the keyword
        assertEquals(listOf(443), AltSvcParser.parse("CLEAR, h3=\":443\"", now)!!.map { it.port })
        assertEquals(listOf(443), AltSvcParser.parse("clear=\":1\", h3=\":443\"", now)!!.map { it.port })
    }

    /**
     * RFC 7838 section 3: alt-authority is `[ uri-host ] ":" port`, and RFC 3986's `port = *DIGIT`; a sign is no digit, so
     * `h3=":+443"` is malformed (before, `toIntOrNull` read it as 443).
     */
    @Test fun negative_altSvcPortWithSignIsSkipped() {
        for (port in listOf("+443", "-443", " 443", "443 ", "0x1bb", "")) {
            assertEquals(emptyList(), AltSvcParser.parse("h3=\":$port\"", now), port)
        }
        assertEquals(listOf(443), AltSvcParser.parse("h3=\":0443\"", now)!!.map { it.port })
    }

    /**
     * RFC 7838 section 3.1: an alternative "is considered fresh for 24 hours from generation of the message", `ma` counts "the
     * number of seconds since the response was generated", and the response age is determined as RFC 7234 section 4.2.3
     * (now RFC 9111 section 4.2.3) says: `corrected_age_value = age_value + response_delay`. The RFC's own example, `Age: 30`
     * with `ma=60`, is fresh for 30 seconds from receipt (minus the transit time). Before, `Age` was ignored and freshness
     * counted from receipt.
     */
    @Test fun negative_altSvcFreshnessAccountsForAge() {
        respond(200, "h3=\":443\"; ma=60", age = listOf("30"))
        assertEquals(now + 30_000, cache.h3For(origin)!!.expiresAtEpochMillis)
        // the response delay counts too
        respond(200, "h3=\":443\"; ma=60", age = listOf("30"), delayMillis = 2_000)
        assertEquals(now + 28_000, cache.h3For(origin)!!.expiresAtEpochMillis)
        // and without Age (age_value 0)
        respond(200, "h3=\":443\"; ma=60", delayMillis = 2_000)
        assertEquals(now + 58_000, cache.h3For(origin)!!.expiresAtEpochMillis)
        // the default 24 hours from generation, a CDN copy 86000 s old: 400 s left, not 24 hours
        respond(200, "h3=\":443\"", age = listOf("86000"))
        assertEquals(now + 400_000, cache.h3For(origin)!!.expiresAtEpochMillis)
        // older than ma: replaces the cached alternatives (section 3.1) and is not fresh
        respond(200, "h3=\":443\"; ma=60", age = listOf("61"))
        assertNull(cache.h3For(origin))
    }

    /**
     * RFC 9111 section 5.1: a list-based Age uses its first member, an invalid one is ignored; a value too large to represent
     * is 2147483648 (section 1.2.2), which makes every alternative stale, not fresh by an overflow.
     */
    @Test fun negative_invalidOrListAgeHandledAsRfc9111Says() {
        respond(200, "h3=\":443\"; ma=60", age = listOf("10, 50"))
        assertEquals(now + 50_000, cache.h3For(origin)!!.expiresAtEpochMillis)
        respond(200, "h3=\":443\"; ma=60", age = listOf("10", "50"))
        assertEquals(now + 50_000, cache.h3For(origin)!!.expiresAtEpochMillis)
        for (bad in listOf("-5", "+5", "abc", "1.5", "")) {
            respond(200, "h3=\":443\"; ma=60", age = listOf(bad))
            assertEquals(now + 60_000, cache.h3For(origin)!!.expiresAtEpochMillis, bad)
        }
        respond(200, "h3=\":443\"; ma=99999999999999999999", age = listOf("99999999999999999999"))
        assertNull(cache.h3For(origin))
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

    /**
     * The alt-authority host must be an RFC 3986 host (RFC 7838 section 3): one with a space, a control character, a line
     * break or a bare IPv6 address is a malformed alternative and is skipped. The host reaches the engine's diagnostics log
     * line (threat-model 3.18), where such text could forge lines; so is a valid one that cannot be a connection target.
     */
    @Test fun negative_altSvcHostThatIsNoUriHostIsSkipped() {
        for (bad in listOf(
            "a b.example",
            "evil\nkuicksilver: GET",
            "x\u0007y",
            "::1",
            "[::1",
            "[zz::1]",
            "[]",
            "a%2",
            "a%zz",
            "a/b",
            "a@b",
        )) {
            val header = "h3=\"$bad:443\""
            assertEquals(emptyList(), AltSvcParser.parse(header, now), header)
        }
        val ok = listOf("alt.example.com", "[2001:db8::1]", "192.0.2.1", "a-b.example")
        for (good in ok) {
            assertEquals(1, AltSvcParser.parse("h3=\"$good:443\"", now)!!.size, good)
        }
        // valid RFC 3986 hosts that no DNS name or address has: no connection target, skipped too (and so never logged)
        for (unusable in listOf("a_b", "a~b", "x%41y", "x),fallback=Other", "sub!delims\$&'()*+;=")) {
            assertTrue(AltSvcParser.isUriHost(unusable), unusable)
            assertEquals(emptyList(), AltSvcParser.parse("h3=\"$unusable:443\"", now), unusable)
        }
        assertEquals("2001:db8::1", AltSvcParser.parse("h3=\"[2001:db8::1]:443\"", now)!!.single().host)
        assertEquals(null, AltSvcParser.parse("h3=\":443\"", now)!!.single().host)
    }

    /**
     * Entries a store hands back are checked as the header was (threat-model 3.14, 3.18): a store file written by an older
     * version or by another program, or an application's own store, cannot aim the client at a local address, an
     * unprivileged port of a privileged origin, a host the parser refuses or a port out of range.
     */
    @Test fun negative_storedAlternativeFailingTheParserRulesIsNotUsed() {
        val o = cache.originOf(origin)
        val exp = now + 60_000
        for (bad in listOf(
            AltSvcEntry("h3", null, 8443, exp, false),
            AltSvcEntry("h3", "127.0.0.1", 443, exp, false),
            AltSvcEntry("h3", "a b", 443, exp, false),
            AltSvcEntry("h3", "x),fallback=Other", 443, exp, false),
            AltSvcEntry("h3", "", 443, exp, false),
            AltSvcEntry("h3", null, 0, exp, false),
            AltSvcEntry("h3", null, 70_000, exp, false),
            AltSvcEntry("h2", null, 443, exp, false),
        )) {
            store.put(o, listOf(bad))
            assertNull(cache.h3For(origin), "$bad")
            store.put(o, listOf(bad, AltSvcEntry("h3", "alt.example.com", 443, exp, false)))
            assertEquals("alt.example.com", cache.h3For(origin)?.host, "$bad")
        }
    }

    /** `clear()` forgets every origin, persistent alternatives included (RFC 7838 section 9.4). */
    @Test fun negative_inMemoryStoreClearForgetsEverything() {
        respond(200, "h3=\":443\"; persist=1")
        respond(200, "h3=\":443\"", url = Url("https://other.example/"))
        store.clear()
        assertNull(cache.h3For(origin))
        assertNull(cache.h3For(Url("https://other.example/")))
    }
}
