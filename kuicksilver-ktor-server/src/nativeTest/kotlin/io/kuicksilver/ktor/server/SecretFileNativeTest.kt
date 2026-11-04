// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.server

import kotlinx.cinterop.CPointer
import kotlinx.io.IOException
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.files.SystemTemporaryDirectory
import platform.posix.FILE
import platform.posix.fclose
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Whether the descriptor under [f] is close-on-exec; null where the platform has no such flag to read (Windows). */
internal expect fun closeOnExecOf(f: CPointer<FILE>): Boolean?

/** `readSecretFile` on Kotlin/Native: what the PEM watcher and EngineMain read the key file with. */
class SecretFileNativeTest {
    private fun tempFile(bytes: ByteArray): Path {
        val p = Path(SystemTemporaryDirectory, "ksl-secret-${Random.nextLong().toULong()}.pem")
        SystemFileSystem.sink(p).use { s ->
            val b = kotlinx.io.Buffer()
            b.write(bytes)
            if (b.size > 0) s.write(b, b.size) // kotlinx-io's FileSink fails on an empty write; the file is created anyway
        }
        return p
    }

    @Test fun contentRoundTrips() {
        val text = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        val p = tempFile(text.encodeToByteArray())
        try {
            assertContentEquals(text.toCharArray(), readSecretFile(p.toString(), 1024))
            assertContentEquals(text.toCharArray(), readSecretFile(p.toString(), text.length.toLong()), "exactly the cap")
        } finally {
            SystemFileSystem.delete(p)
        }
    }

    @Test fun negative_fileAboveTheCapRefused() {
        val p = tempFile(ByteArray(2000) { 'A'.code.toByte() })
        try {
            val e = assertFailsWith<IOException> { readSecretFile(p.toString(), 1999) }
            assertTrue("larger than" in e.message.orEmpty(), e.message)
        } finally {
            SystemFileSystem.delete(p)
        }
    }

    @Test fun emptyFileIsEmpty() {
        val p = tempFile(ByteArray(0))
        try {
            assertEquals(0, readSecretFile(p.toString(), 1024).size)
        } finally {
            SystemFileSystem.delete(p)
        }
    }

    @Test fun negative_missingFileFails() {
        assertFailsWith<IOException> { readSecretFile(Path(SystemTemporaryDirectory, "ksl-no-such-${Random.nextLong()}").toString(), 1024) }
    }

    @Test fun descriptorIsCloseOnExec() {
        val p = tempFile("x".encodeToByteArray())
        try {
            val f = assertNotNull(openSecretFile(p.toString()))
            try {
                closeOnExecOf(f)?.let { assertTrue(it, "the key file's descriptor is not close-on-exec") }
            } finally {
                fclose(f)
            }
        } finally {
            SystemFileSystem.delete(p)
        }
    }
}
