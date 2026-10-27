// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.qlog

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.TlsRole
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import kotlinx.io.readString
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Security review 2026-10-14, finding 5: the client picks a server's trace name, so the sink must not trust it (threat model 3.2). */
class DirectoryQlogSinkTest {
    private val dir = Path(SystemTemporaryDirectory, "ksl-qlog-${Random.nextLong().toULong().toString(16)}")

    @AfterTest fun cleanup() {
        if (SystemFileSystem.exists(dir)) {
            SystemFileSystem.list(dir).forEach { SystemFileSystem.delete(it) }
            SystemFileSystem.delete(dir)
        }
    }

    private fun files() = SystemFileSystem.list(dir).map { it.name }.sorted()

    private fun read(name: String) = SystemFileSystem.source(Path(dir, name)).buffered().use { it.readString() }

    /**
     * Runs [block] unless the sink refuses for want of java.nio.file: on Android API 24-25 it cannot check the directory's
     * permissions and refuses to write diagnostics there (PrivateFiles.jvm.kt), the behaviour these tests cannot exercise.
     * Any other failure still fails the test.
     */
    private inline fun unlessNioFilesMissing(block: () -> Unit) {
        try {
            block()
        } catch (e: IllegalArgumentException) {
            if (e.message?.contains("java.nio.file is unavailable") != true) throw e
        }
    }

    @Test fun negative_reusedOdcidDoesNotTruncateAnotherTrace() =
        unlessNioFilesMissing {
            val sink = DirectoryQlogSink(dir.toString())
            val first = assertNotNull(sink.open("0011223344556677", TlsRole.Server))
            first.write("first\n")
            first.close()
            val second = assertNotNull(sink.open("0011223344556677", TlsRole.Server))
            second.write("second\n")
            second.close()
            val names = files()
            assertEquals(2, names.size, "a reused connection ID gets a file of its own: $names")
            assertTrue(names.all { it.startsWith("0011223344556677_server_") && it.endsWith(".sqlog") }, "$names")
            assertEquals(setOf("first\n", "second\n"), names.map { read(it) }.toSet(), "the first trace is intact")
        }

    @Test fun negative_openTracesAreBoundedPerSink() =
        unlessNioFilesMissing {
            val sink = DirectoryQlogSink(dir.toString(), maxOpenTraces = 2, maxTotalBytes = 1L shl 20)
            val a = assertNotNull(sink.open("aa00000000000000", TlsRole.Server))
            val b = assertNotNull(sink.open("bb00000000000000", TlsRole.Server))
            assertNull(sink.open("cc00000000000000", TlsRole.Server), "a third connection is not traced while two traces are open")
            a.close()
            val c = assertNotNull(sink.open("cc00000000000000", TlsRole.Server), "a closed trace frees its slot")
            b.close()
            c.close()
            assertEquals(3, files().size)
        }

    @Test fun negative_totalBytesAreBoundedPerSink() =
        unlessNioFilesMissing {
            val sink = DirectoryQlogSink(dir.toString(), maxOpenTraces = 8, maxTotalBytes = 100)
            val a = assertNotNull(sink.open("aa00000000000000", TlsRole.Server))
            repeat(20) { a.write("0123456789") } // 200 bytes offered
            a.close()
            assertTrue(read(files().single()).length <= 100, "the trace stops at the sink's lifetime budget")
            assertNull(sink.open("bb00000000000000", TlsRole.Server), "no trace opens once the budget is spent")
        }

    @Test fun negative_nameThatIsNotHexIsRefused() {
        val sink = DirectoryQlogSink(dir.toString())
        assertFailsWith<IllegalArgumentException> { sink.open("../../etc/passwd", TlsRole.Server) }
        assertFailsWith<IllegalArgumentException> { sink.open("", TlsRole.Server) }
    }

    @Test fun ceilingsMustBePositive() {
        assertFailsWith<IllegalArgumentException> { DirectoryQlogSink(dir.toString(), maxOpenTraces = 0, maxTotalBytes = 1) }
        assertFailsWith<IllegalArgumentException> { DirectoryQlogSink(dir.toString(), maxOpenTraces = 1, maxTotalBytes = 0) }
    }
}
