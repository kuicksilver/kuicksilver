// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.convert
import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readString
import kotlinx.io.writeString
import platform.posix.chmod
import platform.posix.getpid
import platform.posix.mkdir
import platform.posix.mkfifo
import platform.posix.rmdir
import platform.posix.symlink
import platform.posix.unlink
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** Diagnostics files (qlog) on Linux: exclusive, never through a link, in a directory only this user can change (threat model 3.2). */
class PrivateFilesLinuxTest {
    private fun tmp(name: String): String = "/tmp/ksl-private-$name-${getpid()}"

    private fun write(
        path: String,
        text: String,
    ) = SystemFileSystem.sink(Path(path)).buffered().use { it.writeString(text) }

    private fun read(path: String) = SystemFileSystem.source(Path(path)).buffered().use { it.readString() }

    @Test fun negative_plantedSymlinkFifoOrFileIsNotUsed() {
        val dir = tmp("dir")
        val victim = tmp("victim")
        checkPrivateDirectory(dir)
        write(victim, "keep")
        try {
            assertEquals(0, symlink(victim, "$dir/link.sqlog"))
            assertNull(createPrivateFile(dir, "link.sqlog"), "a planted symlink is a taken name")
            assertEquals("keep", read(victim), "the link target is untouched")
            assertEquals(0, mkfifo("$dir/fifo.sqlog", 0x180.convert()))
            assertNull(createPrivateFile(dir, "fifo.sqlog"), "a planted FIFO is a taken name, and opening it does not block")
            write("$dir/file.sqlog", "other")
            assertNull(createPrivateFile(dir, "file.sqlog"))
            assertEquals("other", read("$dir/file.sqlog"), "an existing file is not truncated")
            val w = assertNotNull(createPrivateFile(dir, "new.sqlog"))
            w.write("ok".encodeToByteArray())
            w.close()
            assertEquals("ok", read("$dir/new.sqlog"))
        } finally {
            listOf("link", "fifo", "file", "new").forEach { unlink("$dir/$it.sqlog") }
            rmdir(dir)
            unlink(victim)
        }
    }

    @Test fun negative_sharedOrLinkedDirectoryRefused() {
        val shared = tmp("shared")
        val link = tmp("dirlink")
        val target = tmp("dirtarget")
        try {
            assertEquals(0, mkdir(shared, 0x1C0.convert()))
            assertEquals(0, chmod(shared, 0x1FF.convert())) // 0777: another user could swap our files
            assertFailsWith<IllegalArgumentException> { checkPrivateDirectory(shared) }
            assertEquals(0, chmod(shared, 0x3FF.convert())) // 01777: sticky, others cannot remove or rename our files
            checkPrivateDirectory(shared)
            assertEquals(0, mkdir(target, 0x1C0.convert()))
            assertEquals(0, symlink(target, link))
            assertFailsWith<IllegalArgumentException> { checkPrivateDirectory(link) }
        } finally {
            rmdir(shared)
            unlink(link)
            rmdir(target)
        }
    }
}
