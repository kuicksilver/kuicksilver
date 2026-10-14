// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import platform.posix.O_CREAT
import platform.posix.O_WRONLY
import platform.posix.chmod
import platform.posix.close
import platform.posix.getpid
import platform.posix.link
import platform.posix.mkfifo
import platform.posix.open
import platform.posix.stat
import platform.posix.symlink
import platform.posix.unlink
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

/** `keylogFile` on POSIX: the file is opened without following symlinks and its mode is tightened to 0600 (threat model section 3.7). */
class KeylogFileAppleTest {
    private fun tmp(name: String): String = "/tmp/ksl-keylog-$name-${getpid()}.txt".also { unlink(it) }

    private fun modeOf(path: String): Int =
        memScoped {
            val st = alloc<stat>()
            assertEquals(0, stat(path, st.ptr), "stat $path")
            st.st_mode.toInt() and 0x1FF
        }

    private fun sizeOf(path: String): Long =
        memScoped {
            val st = alloc<stat>()
            assertEquals(0, stat(path, st.ptr), "stat $path")
            st.st_size
        }

    @Test fun negative_keylogFileExistingModeTightened() {
        val path = tmp("mode")
        val fd = open(path, O_WRONLY or O_CREAT, 0x1A4 /* 0644 */)
        assertTrue(fd >= 0)
        close(fd)
        chmod(path, 0x1A4u) // umask-proof
        assertEquals(0x1A4, modeOf(path))
        try {
            keylogFile(path).log("X")
            assertEquals(0x180 /* 0600 */, modeOf(path))
            assertEquals(2L, sizeOf(path))
        } finally {
            unlink(path)
        }
    }

    @Test fun negative_keylogFileRefusesSymlink() {
        val target = tmp("target")
        val link = tmp("link")
        val fd = open(target, O_WRONLY or O_CREAT, 0x180)
        assertTrue(fd >= 0)
        close(fd)
        assertEquals(0, symlink(target, link))
        try {
            assertFails { keylogFile(link).log("X") }
            assertEquals(0L, sizeOf(target), "nothing was written through the symlink")
        } finally {
            unlink(link)
            unlink(target)
        }
    }

    @Test fun negative_keylogFileRefusesHardlink() {
        val target = tmp("hard-target")
        val hard = tmp("hard-link")
        val fd = open(target, O_WRONLY or O_CREAT, 0x180)
        assertTrue(fd >= 0)
        close(fd)
        assertEquals(0, link(target, hard))
        try {
            assertFails { keylogFile(hard).log("X") }
            assertEquals(0L, sizeOf(target), "nothing was written through the hard link")
        } finally {
            unlink(hard)
            unlink(target)
        }
    }

    /** A FIFO at the path is refused instead of blocking until a reader appears (security review 2026-10-14, finding 6). */
    @Test fun negative_keylogFileRefusesFifo() {
        val fifo = tmp("fifo")
        assertEquals(0, mkfifo(fifo, 0x180u))
        try {
            assertFails { keylogFile(fifo) }
        } finally {
            unlink(fifo)
        }
    }

    /** Native reopens per line: a FIFO swapped in after the sink was made drops the line instead of stalling the caller (the loop). */
    @Test fun negative_keylogFifoSwappedInLaterDoesNotBlock() {
        val path = tmp("swap")
        val sink = keylogFile(path)
        unlink(path)
        assertEquals(0, mkfifo(path, 0x180u))
        try {
            sink.log("X") // returns: no reader, the nonblocking open fails and the line is dropped
        } finally {
            unlink(path)
        }
    }
}
