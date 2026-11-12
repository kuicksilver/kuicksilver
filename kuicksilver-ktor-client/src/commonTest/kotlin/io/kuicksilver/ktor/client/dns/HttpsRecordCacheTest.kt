// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.client.dns

import io.kuicksilver.ktor.client.ExpiryClock
import io.kuicksilver.ktor.client.HttpsRecordSource
import io.kuicksilver.ktor.client.isSecure
import io.kuicksilver.ktor.client.lookup
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/** The HTTPS record cache and lookups of the engine (bounds, TTLs, one lookup per name) and the DoH exchange's query. */
class HttpsRecordCacheTest {
    private fun rec(
        owner: String,
        ttl: Long,
    ) = SvcbRecord(1, ".", listOf("h3"), false, null, emptyList(), emptyList(), ttl, owner)

    @Test fun ttlKeptAndBounded() {
        var now = 0L
        val cache = HttpsRecordCache(ExpiryClock { now })
        cache.put("short.example", listOf(rec("short.example", 5)), null)
        cache.put("long.example", listOf(rec("long.example", 10_000_000)), null)
        cache.put("none.example", emptyList(), 120)
        cache.put("nosoa.example", emptyList(), null)
        assertNull(cache.get("nosoa.example")) // RFC 2308 section 5: no SOA, no negative caching
        now = 4_999
        assertEquals(1, cache.get("short.example")?.size) // never longer than the TTL (RFC 1035 section 3.2.1)
        now = 5_000
        assertNull(cache.get("short.example"))
        now = 119_999
        assertEquals(emptyList(), cache.get("none.example")) // the SOA's negative TTL
        now = 120_000
        assertNull(cache.get("none.example"))
        now = 86_399_999
        assertEquals(1, cache.get("long.example")?.size) // capped at a day
        now = 86_400_000
        assertNull(cache.get("long.example"))
        for (i in 0 until 1500) cache.put("o$i.example", listOf(rec("o$i.example", 300)), null)
        assertEquals(HttpsRecordCache.MAX_NAMES, cache.size)
        assertNull(cache.get("o0.example")) // the least recently used went first
        assertEquals(1, cache.get("o1499.example")?.size)
    }

    @Test fun negative_wallClockAloneExpiresAnEntry() {
        // the monotonic clock stops while a device sleeps: the wall clock still sees the TTL pass
        var mono = 0L
        var wall = 1_000_000L
        val cache = HttpsRecordCache(ExpiryClock({ mono }, { wall }))
        cache.put("a.example", listOf(rec("a.example", 60)), null)
        cache.putAddresses("a.example", listOf(ByteArray(4)), 60)
        mono = 1_000 // a second awake, then the device slept for an hour
        wall += 3_600_000
        assertNull(cache.get("a.example"))
        assertNull(cache.addressesOf("a.example"))
    }

    @Test fun negative_wallClockSteppedBackDoesNotExtendAnEntry() {
        // a wall clock stepped back (NTP, by hand): the monotonic clock still sees the TTL pass
        var mono = 0L
        var wall = 1_000_000L
        val cache = HttpsRecordCache(ExpiryClock({ mono }, { wall }))
        cache.put("a.example", listOf(rec("a.example", 60)), null)
        wall -= 3_600_000
        mono = 59_999
        assertEquals(1, cache.get("a.example")?.size)
        mono = 60_000
        assertNull(cache.get("a.example"))
    }

    @Test fun oneLookupPerNameAndFailuresNotCached() =
        runTest {
            var calls = 0
            val gate = CompletableDeferred<Unit>()
            var fail = true
            val records =
                HttpsRecords({ name ->
                    calls++
                    gate.await()
                    if (fail) null else DnsAnswer(listOf(rec(name, 300)))
                }, backgroundScope, 10.seconds, ExpiryClock { testScheduler.currentTime })
            val a = async { records.records("a.example") }
            val b = async { records.records("a.example") }
            testScheduler.runCurrent()
            gate.complete(Unit)
            assertNull(a.await())
            assertNull(b.await())
            assertEquals(1, calls)
            fail = false
            assertEquals(1, records.records("a.example")?.size) // the failure was not stored
            assertEquals(1, records.records("a.example")?.size) // the answer was
            assertEquals(2, calls)
        }

    @Test fun negative_hangingLookupIsBoundedByTheQueryTimeout() =
        runTest {
            var calls = 0
            val records =
                HttpsRecords({
                    calls++
                    awaitCancellation()
                }, backgroundScope, 10.seconds, ExpiryClock { testScheduler.currentTime })
            assertNull(records.records("a.example")) // virtual time: ends at the query timeout
            assertEquals(10_000, testScheduler.currentTime)
            assertNull(records.records("a.example")) // nothing stuck in flight: asked again
            assertEquals(2, calls)
        }

    @Test fun exchangeSourceBuildsRfc8484Query() =
        runTest {
            var query = ByteArray(0)
            val lookup =
                HttpsRecordSource
                    .Exchange { q ->
                        query = q
                        SvcbTestEncoder.response(
                            "a.example",
                            listOf(SvcbTestEncoder.rr("a.example", 65, 300, SvcbTestEncoder.encode(rec("a.example", 300)))),
                        )
                    }.lookup(1.seconds)!!
            assertEquals(listOf("h3"), lookup("a.example")?.records?.single()?.alpn)
            // ID 0, RD, one question for a.example HTTPS IN (RFC 8484 section 4.1)
            assertContentEquals(hex("0000 0100 0001 0000 0000 0000 0161 076578616d706c65 00 0041 0001"), query)
        }

    @Test fun protectedSystemIsSecureWhenItsCheckSaysSo() { // RFC 9460 section 3.1, per request
        var strict = false
        val source = HttpsRecordSource.ProtectedSystem { strict }
        assertEquals(false, source.isSecure())
        strict = true
        assertEquals(true, source.isSecure())
        assertEquals(false, HttpsRecordSource.ProtectedSystem { throw IllegalStateException("no network") }.isSecure())
        assertEquals(false, HttpsRecordSource.System.isSecure())
        assertEquals(true, HttpsRecordSource.Exchange(secure = true) { it }.isSecure())
    }

    @Test fun negative_exchangeThatFailsOrAnswersAnotherQuestionIsAFailedLookup() =
        runTest {
            assertNull(HttpsRecordSource.Exchange { throw IllegalStateException("DoH server down") }.lookup(1.seconds)!!("a.example"))
            assertNull(
                HttpsRecordSource
                    .Exchange { SvcbTestEncoder.response("b.example", emptyList()) }
                    .lookup(1.seconds)!!("a.example"),
            )
            assertNull(HttpsRecordSource.Off.lookup(1.seconds))
        }
}
