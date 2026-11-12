// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import kotlinx.coroutines.runBlocking
import java.io.File
import java.lang.management.ManagementFactory
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * The guard of 3cd5db6e5 without a device: a 32 MiB `respondBytes` over HTTP/2 ([respondBytesOverH2]) in a JVM of its own
 * whose heap holds one copy of the content but not two. It tells one whole copy from two; it is not Android's 48 MiB
 * heap (an Android 10 image ran the whole-array copy out of memory there; `ServerH2ResponseTest.largeBytesResponseGoesOutWhole`
 * runs on the device). The server's array takes 32 MiB and the engine as it is sends it a 16 KiB slice at a time; a
 * respondFromBytes that copies it whole (a `ByteReadChannel` over the array, as before 3cd5db6e5) needs a second 32 MiB.
 * With the flags below (measured on the JVM 21 host): the engine as it is needs more than 48 MiB of heap and passes from
 * 52 MiB; the whole-array copy fails up to 72 MiB and passes from 80 MiB. [HEAP] is 64 MiB, between the two.
 *
 * The forked JVM is the same on every host, whatever its ergonomics would pick: Parallel GC with an 8 MiB young
 * generation (the 32 MiB arrays live in the old generation, whose size is then the heap less 8 MiB), its GC overhead
 * limit, which turns a heap thrashing near its limit into an OutOfMemoryError, and `-XX:+ExitOnOutOfMemoryError`, so it
 * ends at once instead of grinding on. It is stopped after [LIMIT_SECONDS] anyway, and its output goes to a file, so a
 * forked JVM that does not end never holds the test.
 */
class RespondBytesHeapJvmTest {
    @Test fun negative_largeBytesResponseFitsAHeapWithoutRoomForACopy() {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val dir = File(System.getProperty("java.io.tmpdir"))
        // the classpath in a JDK @argfile: a command line on Windows holds at most 32 767 characters
        val argFile = File.createTempFile("respond-bytes-heap", ".args", dir)
        val output = File.createTempFile("respond-bytes-heap", ".log", dir)
        try {
            val cp = System.getProperty("java.class.path").replace("\\", "\\\\").replace("\"", "\\\"")
            argFile.writeText("-cp\n\"$cp\"\n")
            // the native library is found as in this JVM (its kuicksilver.* and ksl.* properties), and the test JVM's
            // module and native-access flags (-Pkuicksilver.test.jvmArgs) hold there too; never its heap, agents or debugger
            val props =
                System
                    .getProperties()
                    .stringPropertyNames()
                    .filter { it.startsWith("ksl.") || it.startsWith("kuicksilver.") }
                    .map { "-D$it=${System.getProperty(it)}" }
            val flags =
                ManagementFactory.getRuntimeMXBean().inputArguments.filter { a ->
                    FORWARDED.any { a.startsWith(it) }
                }
            val cmd =
                listOf(java, "-Xmx$HEAP", "-Xmn8m", "-XX:+UseParallelGC", "-XX:+UseGCOverheadLimit", "-XX:+ExitOnOutOfMemoryError") +
                    flags + props + "@${argFile.path}" + RespondBytesHeapMain::class.java.name
            val p = ProcessBuilder(cmd).redirectErrorStream(true).redirectOutput(output).start()
            if (!p.waitFor(LIMIT_SECONDS, TimeUnit.SECONDS)) {
                p.destroyForcibly()
                p.waitFor(10, TimeUnit.SECONDS)
                fail("the forked JVM did not end within $LIMIT_SECONDS s (GC thrash?):\n${output.readText()}")
            }
            assertEquals(0, p.exitValue(), "32 MiB through respondBytes with a $HEAP heap:\n${output.readText()}")
        } finally {
            argFile.delete()
            output.delete()
        }
    }

    private companion object {
        /** One copy of the 32 MiB content and the engine fit (from 52 MiB); a second copy does not (up to 72 MiB). */
        const val HEAP = "64m"

        const val LIMIT_SECONDS = 120L

        /** The test JVM's flags the forked JVM takes over. */
        val FORWARDED =
            listOf("--enable-native-access", "--illegal-native-access", "--add-opens", "--add-exports", "--add-modules")
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
