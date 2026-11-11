// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.tls.TlsRole
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The Android qlog helper's directory rules ([qlogDirectory] on the app's cache directory), on the host JVM. */
class QlogDirectoryHostTest {
    private val parent = Files.createTempDirectory("qlog-parent").toFile()

    @AfterTest fun cleanup() {
        parent.deleteRecursively()
    }

    private fun modeOf(f: File) = PosixFilePermissions.toString(Files.getPosixFilePermissions(f.toPath()))

    @Test fun createsAnOwnerOnlyDirectoryAndWritesTracesThere() {
        val sink = qlogDirectoryIn(parent, "kuicksilver-qlog")
        val dir = File(parent, "kuicksilver-qlog")
        assertTrue(dir.isDirectory, "created before the first connection")
        assertEquals("rwx------", modeOf(dir))
        val trace = assertNotNull(sink.open("0a1b", TlsRole.Client))
        trace.write("{}\n")
        trace.close()
        val files = dir.listFiles().orEmpty()
        assertEquals(1, files.size)
        assertTrue(files[0].name.startsWith("0a1b_client_") && files[0].name.endsWith(".sqlog"), files[0].name)
        assertEquals("rw-------", modeOf(files[0]))
    }

    @Test fun negative_nameMustBeOnePathComponent() {
        for (bad in listOf("", ".", "..", "a/b", "../up", "a\\b")) {
            assertFailsWith<IllegalArgumentException>(bad) { qlogDirectoryIn(parent, bad) }
        }
        assertEquals(0, parent.listFiles().orEmpty().size, "nothing was created")
    }

    @Test fun negative_directoryWritableByOthersRefused() {
        val dir = File(parent, "shared").also { it.mkdir() }
        Files.setPosixFilePermissions(dir.toPath(), PosixFilePermissions.fromString("rwxrwxrwx"))
        assertFailsWith<IllegalArgumentException> { qlogDirectoryIn(parent, "shared") }
    }

    @Test fun negative_symbolicLinkRefused() {
        val target = File(parent, "elsewhere").also { it.mkdir() }
        Files.createSymbolicLink(File(parent, "link").toPath(), target.toPath())
        assertFailsWith<IllegalArgumentException> { qlogDirectoryIn(parent, "link") }
    }
}
