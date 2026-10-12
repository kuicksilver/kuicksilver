// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.writeString
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The persistent [AltSvcStore] (alternatives survive a restart so the first request after a cold start can use HTTP/3). */
class FileAltSvcStoreTest {
    private var now = 1_000_000L
    private val created = ArrayList<Path>()

    private fun tmp(): Path = Path(SystemTemporaryDirectory, "altsvc-${Random.nextLong()}.tsv").also { created += it }

    @AfterTest fun cleanup() {
        for (p in created) {
            SystemFileSystem.delete(p, mustExist = false)
            SystemFileSystem.delete(
                Path(p.parent ?: Path("."), p.name + ".tmp"),
                mustExist = false,
            )
        }
    }

    private fun entry(
        port: Int,
        host: String? = null,
        persist: Boolean = false,
        ttl: Long = 60_000,
    ) = AltSvcEntry(
        "h3",
        host,
        port,
        now + ttl,
        persist,
    )

    @Test fun missingFileIsEmptyAndCreatedOnFirstPut() {
        val p = tmp()
        val s = FileAltSvcStore(p) { now }
        assertTrue(s.get("https://a:443").isEmpty())
        assertTrue(!SystemFileSystem.exists(p))
        s.put("https://a:443", listOf(entry(8443)))
        assertTrue(SystemFileSystem.exists(p))
    }

    @Test fun entriesSurviveANewInstance() {
        val p = tmp()
        FileAltSvcStore(p) { now }.put("https://a:443", listOf(entry(8443, host = "alt.example", persist = true), entry(9443)))
        val again = FileAltSvcStore(p) { now }.get("https://a:443")
        assertEquals(listOf("alt.example" to 8443, null to 9443), again.map { it.host to it.port })
        assertTrue(again[0].persist && !again[1].persist)
        assertEquals(now + 60_000, again[0].expiresAtEpochMillis)
    }

    @Test fun removeAndClearNonPersistentArePersisted() {
        val p = tmp()
        val s = FileAltSvcStore(p) { now }
        s.put("https://a:443", listOf(entry(1), entry(2, persist = true)))
        s.put("https://b:443", listOf(entry(3)))
        s.clearNonPersistent()
        s.remove("https://c:443")
        val again = FileAltSvcStore(p) { now }
        assertEquals(listOf(2), again.get("https://a:443").map { it.port })
        assertTrue(again.get("https://b:443").isEmpty())
        again.remove("https://a:443")
        assertTrue(FileAltSvcStore(p) { now }.get("https://a:443").isEmpty())
    }

    /** The same alternatives again (the usual case: every response repeats the origin's `Alt-Svc`) do not rewrite the file. */
    @Test fun identicalPutDoesNotRewrite() {
        val p = tmp()
        val s = FileAltSvcStore(p) { now }
        val entries = listOf(entry(8443), entry(9443, host = "alt.example", persist = true))
        s.put("https://a:443", entries)
        SystemFileSystem.delete(p)
        s.put("https://a:443", entries)
        assertTrue(!SystemFileSystem.exists(p), "an identical put is not written")
        s.put("https://a:443", listOf(entry(8443)))
        assertTrue(SystemFileSystem.exists(p), "a different list is written")
    }

    /** A repeated header only moves the expiry; the file is rewritten once the shift reaches half the new lifetime. */
    @Test fun refreshedExpiryRewrittenOnlyPastHalfLifetime() {
        val p = tmp()
        val s = FileAltSvcStore(p) { now }
        s.put("https://a:443", listOf(entry(8443)))
        SystemFileSystem.delete(p)
        now += 10_000
        s.put("https://a:443", listOf(entry(8443)))
        assertTrue(!SystemFileSystem.exists(p), "a 10 s shift of a 60 s lifetime is not written")
        now += 30_000
        s.put("https://a:443", listOf(entry(8443)))
        assertTrue(SystemFileSystem.exists(p), "a 40 s shift is written")
        assertEquals(now + 60_000, FileAltSvcStore(p) { now }.get("https://a:443").single().expiresAtEpochMillis)
    }

    /** Behind an [AltSvcCache] the store only snapshots under the engine's lock; the write runs later, and an older snapshot never overwrites a newer one. */
    @Test fun writesBehindTheCacheAreDeferredAndOrdered() {
        val p = tmp()
        val s = FileAltSvcStore(p) { now }
        val cache = AltSvcCache(s) { now }
        cache.onResponse(Url("https://a/"), 200, listOf("h3=\":443\""), verifiedTls = true)
        assertTrue(!SystemFileSystem.exists(p), "nothing is written under the lock")
        val first = assertNotNull(cache.takePendingWrite())
        cache.onResponse(Url("https://b/"), 200, listOf("h3=\":443\""), verifiedTls = true)
        val second = assertNotNull(cache.takePendingWrite())
        assertNull(cache.takePendingWrite())
        second()
        first()
        assertEquals(1, FileAltSvcStore(p) { now }.get("https://b:443").size, "the older snapshot did not overwrite the newer one")
    }

    /** The file never grows past `AltSvcCache.MAX_ORIGINS` origins: the least recently used ones go (threat-model 3.18). */
    @Test fun negative_altSvcStoreBoundedOrigins() {
        val p = tmp()
        val s = FileAltSvcStore(p) { now }
        for (i in 0 until 1500) s.put("https://o$i:443", listOf(entry(8443)))
        assertTrue(s.get("https://o0:443").isEmpty(), "the oldest origin was evicted")
        assertEquals(1, s.get("https://o1499:443").size)
        val again = FileAltSvcStore(p) { now }
        val kept = (0 until 1500).count { again.get("https://o$it:443").isNotEmpty() }
        assertTrue(kept <= AltSvcCache.MAX_ORIGINS, "$kept origins reloaded")
        assertEquals(AltSvcCache.MAX_ORIGINS, kept)
    }

    @Test fun expiredAndMalformedLinesAreDroppedOnLoad() {
        val p = tmp()
        SystemFileSystem.sink(p).buffered().use {
            it.writeString(
                "https://a:443\th3\t\t8443\t${now - 1}\t0\nthis is not a record\nhttps://a:443\th3\talt\t9443\t${now + 5000}\t1\nhttps://b:443\th3\t\tnotaport\t1\t0\n",
            )
        }
        val s = FileAltSvcStore(p) { now }
        assertEquals(listOf("alt" to 9443), s.get("https://a:443").map { it.host to it.port })
        assertTrue(s.get("https://b:443").isEmpty())
        assertNull(s.get("https://a:443").firstOrNull { it.port == 8443 }, "the expired entry is gone")
    }
}
