// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import java.io.File
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The diagnostics files (qlog) are created exclusively and never through a link, in a directory only this user can change
 * (security review 2026-10-14, finding 5; threat model 3.2).
 */
class PrivateFilesJvmTest {
    private val posix = "posix" in FileSystems.getDefault().supportedFileAttributeViews()
    private val root = Files.createTempDirectory("ksl-private").toFile()

    @AfterTest fun cleanup() {
        root.walkBottomUp().forEach { Files.deleteIfExists(it.toPath()) }
    }

    @Test fun createsOwnerOnlyDirectoryAndFile() {
        val dir = File(root, "a/b/qlog")
        checkPrivateDirectory(dir.path)
        val w = assertNotNull(createPrivateFile(dir.path, "x.sqlog"))
        w.write("hello".encodeToByteArray())
        w.close()
        assertEquals("hello", File(dir, "x.sqlog").readText())
        if (posix) {
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.toPath())))
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(File(dir, "x.sqlog").toPath())))
        }
    }

    @Test fun negative_plantedSymlinkIsNotFollowed() {
        if (!posix) return
        val victim = File(root, "victim.txt").apply { writeText("keep") }
        val dir = File(root, "q").apply { mkdir() }
        Files.createSymbolicLink(File(dir, "x.sqlog").toPath(), victim.toPath())
        assertNull(createPrivateFile(dir.path, "x.sqlog"), "a planted symlink counts as a taken name")
        Files.createSymbolicLink(File(dir, "dangling.sqlog").toPath(), File(root, "nothing-yet").toPath())
        assertNull(createPrivateFile(dir.path, "dangling.sqlog"), "a dangling symlink is not followed to create its target")
        assertEquals("keep", victim.readText(), "the link target is untouched")
        assertTrue(!File(root, "nothing-yet").exists())
    }

    @Test fun negative_existingFileIsNotTruncated() {
        val dir = File(root, "q").apply { mkdir() }
        File(dir, "x.sqlog").writeText("other trace")
        assertNull(createPrivateFile(dir.path, "x.sqlog"))
        assertEquals("other trace", File(dir, "x.sqlog").readText())
    }

    @Test fun negative_plantedFifoDoesNotBlock() {
        if (!posix) return
        val dir = File(root, "q").apply { mkdir() }
        val fifo = File(dir, "x.sqlog")
        assertEquals(0, ProcessBuilder("mkfifo", fifo.path).start().waitFor())
        var result: Any? = "pending"
        val t = Thread { result = runCatching { createPrivateFile(dir.path, "x.sqlog") }.getOrElse { it } }
        t.start()
        t.join(TimeUnit.SECONDS.toMillis(10))
        assertTrue(!t.isAlive, "creating over a FIFO returned instead of blocking for a reader")
        assertNull(result, "the FIFO's name is taken")
    }

    @Test fun negative_sharedOrLinkedDirectoryRefused() {
        if (!posix) return
        val shared = File(root, "shared").apply { mkdir() }
        Files.setPosixFilePermissions(shared.toPath(), PosixFilePermissions.fromString("rwxrwxrwx"))
        assertFailsWith<IllegalArgumentException> { checkPrivateDirectory(shared.path) }
        val groupWritable = File(root, "group").apply { mkdir() }
        Files.setPosixFilePermissions(groupWritable.toPath(), PosixFilePermissions.fromString("rwxrwx---"))
        assertFailsWith<IllegalArgumentException> { checkPrivateDirectory(groupWritable.path) }
        val target = File(root, "target").apply { mkdir() }
        val link = File(root, "link")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        assertFailsWith<IllegalArgumentException> { checkPrivateDirectory(link.path) }
        val notDir = File(root, "file").apply { writeText("x") }
        assertFailsWith<IllegalArgumentException> { checkPrivateDirectory(notDir.path) }
    }

    @Test fun stickySharedDirectoryAccepted() {
        if (!posix || "unix" !in FileSystems.getDefault().supportedFileAttributeViews()) return
        val sticky = File(root, "sticky").apply { mkdir() }
        assertEquals(0, ProcessBuilder("chmod", "1777", sticky.path).start().waitFor())
        checkPrivateDirectory(sticky.path) // others cannot remove or rename this user's files there
    }

    @Test fun negative_nameWithSeparatorRefused() {
        val dir = File(root, "q").apply { mkdir() }
        assertFailsWith<IllegalArgumentException> { createPrivateFile(dir.path, "../escape") }
        assertFailsWith<IllegalArgumentException> { createPrivateFile(dir.path, "..") }
    }
}
