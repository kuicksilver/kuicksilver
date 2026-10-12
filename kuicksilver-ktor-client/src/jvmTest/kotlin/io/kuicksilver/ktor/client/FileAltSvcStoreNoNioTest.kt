// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import kotlinx.io.IOException
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Android API 24-25 has no `java.nio.file`, so kotlinx-io's `SystemFileSystem.atomicMove` throws
 * `UnsupportedOperationException` there (CI run 38292521169, android (24)): the store must still persist.
 */
class FileAltSvcStoreNoNioTest {
    private val now = 1_000_000L
    private val p = Path(SystemTemporaryDirectory, "altsvc-${Random.nextLong().toULong()}.tsv")

    @AfterTest fun cleanup() = SystemFileSystem.delete(p, mustExist = false)

    private fun entry(port: Int) = AltSvcEntry("h3", null, port, now + 60_000, true)

    @Test fun persistsWhenAtomicMoveIsUnsupported() {
        val s = FileAltSvcStore(p) { now }
        s.atomicMove = { _, _ -> throw UnsupportedOperationException("Atomic move not supported") }
        s.put("https://a:443", listOf(entry(8443)))
        assertEquals(listOf(8443), FileAltSvcStore(p) { now }.get("https://a:443").map { it.port })
    }

    @Test fun aFailingWriteIsReportedOnce() {
        val warnings = ArrayList<String>()
        val s = FileAltSvcStore(p) { now }
        s.atomicMove = { _, _ -> throw IOException("disk full") }
        s.warn = { warnings += it }
        s.put("https://a:443", listOf(entry(8443)))
        s.put("https://b:443", listOf(entry(9443)))
        assertEquals(1, warnings.size, warnings.toString())
        assertEquals(listOf(9443), s.get("https://b:443").map { it.port }) // still works in memory
    }
}
