// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.writeString
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
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
