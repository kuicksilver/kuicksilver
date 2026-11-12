// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import java.io.File
import java.nio.file.Files
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * `FileAltSvcStore(java.io.File)`, the form an Android app writes (`File(context.filesDir, ...)`): it persists like the
 * `kotlinx.io.files.Path` one, and nothing it runs references `java.nio.file`, which Android API 24-25 lack (the device test
 * FileAltSvcStoreAndroidTest runs it there).
 */
class FileAltSvcStoreFileTest {
    private val now = 1_000_000L
    private val dir = Files.createTempDirectory("altsvc-file").toFile()

    @AfterTest fun cleanup() {
        dir.deleteRecursively()
    }

    private fun entry(port: Int) = AltSvcEntry("h3", null, port, now + 60_000, true)

    @Test fun storeFromAFilePersists() {
        val f = File(dir, "altsvc-${Random.nextLong().toULong()}.tsv")
        val s = FileAltSvcStore(f) { now }
        s.atomicMove = { _, _ -> throw UnsupportedOperationException("Atomic move not supported") } // as below API 26
        s.put("https://a:443", listOf(entry(8443)))
        assertTrue(f.isFile, "written to the file given")
        assertEquals(listOf(8443), FileAltSvcStore(f) { now }.get("https://a:443").map { it.port })
    }

    /**
     * The classes of the store and of its `java.io.File` factory never name `java.nio.file`: on Android API 24-25 such a
     * reference fails when the code that holds it runs (NoClassDefFoundError), and desugaring does not provide the package.
     */
    @Test fun negative_storeClassesReferenceNoJavaNioFile() {
        val classes =
            listOf(
                FileAltSvcStore::class.java,
                Class.forName("io.kuicksilver.ktor.client.FileAltSvcStore_jvmCommonKt"),
            )
        val nested =
            classes.flatMap { c ->
                val dirOf = c.name.substringBeforeLast('.').replace('.', '/')
                val prefix = c.simpleName.ifEmpty { c.name.substringAfterLast('.') }
                val url = c.getResource("/$dirOf/") ?: return@flatMap emptyList()
                if (url.protocol != "file") return@flatMap emptyList()
                File(url.toURI()).listFiles().orEmpty().filter { it.name.startsWith("$prefix$") && it.name.endsWith(".class") }.map {
                    Class.forName(c.name.substringBeforeLast('.') + "." + it.name.removeSuffix(".class"))
                }
            }
        for (c in classes + nested) {
            val bytes =
                c.getResourceAsStream("/" + c.name.replace('.', '/') + ".class")?.use { it.readBytes() }
                    ?: fail("no class file for ${c.name}")
            // the constant pool holds every class a class file refers to, as modified UTF-8 (plain ASCII here)
            assertTrue("java/nio/file" !in String(bytes, Charsets.ISO_8859_1), "${c.name} refers to java.nio.file")
        }
    }
}
