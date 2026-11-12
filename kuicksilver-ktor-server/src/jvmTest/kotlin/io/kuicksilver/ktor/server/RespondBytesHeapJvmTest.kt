// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The guard of 3cd5db6e5 without a device: a 32 MiB `respondBytes` over HTTP/2 ([respondBytesOverH2]) in a JVM of its own
 * with a 48 MiB heap, the growth limit of an Android 10 image. The server's array takes 32 MiB; a respondFromBytes that
 * copies it whole (a `ByteReadChannel` over the array) needs 64 MiB and fails there with an OutOfMemoryError, as it did
 * on Android 10, while the engine as it is sends it a 16 KiB slice at a time.
 */
class RespondBytesHeapJvmTest {
    @Test fun negative_largeBytesResponseFitsA48MiBHeap() {
        val java = File(System.getProperty("java.home"), "bin/java").path
        // the native library is found as in this JVM (its kuicksilver.* and ksl.* properties)
        val props =
            System
                .getProperties()
                .stringPropertyNames()
                .filter { it.startsWith("ksl.") || it.startsWith("kuicksilver.") }
                .map { "-D$it=${System.getProperty(it)}" }
        val cmd =
            listOf(java, "-Xmx48m", "-cp", System.getProperty("java.class.path")) + props +
                RespondBytesHeapMain::class.java.name
        val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        assertTrue(p.waitFor(120, TimeUnit.SECONDS), "the forked JVM ended")
        assertEquals(0, p.exitValue(), "32 MiB through respondBytes with a 48 MiB heap:\n$out")
    }
}

/** The forked JVM of [RespondBytesHeapJvmTest]: exit status 0 when the whole response went out and arrived intact. */
object RespondBytesHeapMain {
    @JvmStatic fun main(args: Array<String>) {
        val failure =
            runCatching {
                io.kuicksilver.native.KslLoader
                    .ensureLoaded()
                runBlocking { respondBytesOverH2(32 shl 20) }
            }.exceptionOrNull()
        if (failure != null) {
            failure.printStackTrace()
            exitProcess(1)
        }
        exitProcess(0)
    }
}
