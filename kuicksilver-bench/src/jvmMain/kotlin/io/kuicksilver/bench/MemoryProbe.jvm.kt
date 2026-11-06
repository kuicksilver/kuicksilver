// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

import java.lang.management.ManagementFactory
import javax.management.ObjectName

internal actual object MemoryProbe {
    actual val runtime: String = "JVM ${System.getProperty("java.version")}"
    private val threads = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean

    actual fun liveHeapBytes(): Long {
        System.gc(); System.gc() // the second pass also collects what the first one's reference processing released
        return ManagementFactory.getMemoryMXBean().heapMemoryUsage.used
    }

    /** `ps` (macOS has no /proc and the JDK exposes no resident size); VmRSS on Linux. */
    actual fun rssBytes(): Long {
        val status = java.io.File("/proc/self/status")
        if (status.exists()) return status.readLines().firstOrNull { it.startsWith("VmRSS:") }?.split(Regex("\\s+"))?.getOrNull(1)?.toLongOrNull()?.times(1024) ?: -1
        return try {
            val p = ProcessBuilder("ps", "-o", "rss=", "-p", ProcessHandle.current().pid().toString()).redirectErrorStream(true).start()
            val text = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            text.toLongOrNull()?.times(1024) ?: -1
        } catch (_: Exception) { -1 }
    }

    /** The JDK has no view of the C heap; the Native run reports it. */
    actual fun mallocInUseBytes(): Long = -1

    actual fun allocationCounter(): AllocationCounter = object : AllocationCounter {
        private val start = threads.totalThreadAllocatedBytes
        override fun tick() = Unit
        override fun allocated(): Long = threads.totalThreadAllocatedBytes - start
        override fun caveat(): String? = null
    }

    /** `GC.class_histogram` through the DiagnosticCommand MBean (it runs a full collection first). */
    actual fun classHistogram(): Map<String, LongArray>? = try {
        val text = ManagementFactory.getPlatformMBeanServer().invoke(
            ObjectName("com.sun.management:type=DiagnosticCommand"), "gcClassHistogram", arrayOf<Any>(arrayOf<String>()), arrayOf(Array<String>::class.java.name),
        ) as String
        val rows = HashMap<String, LongArray>()
        for (line in text.lineSequence()) {
            val f = line.trim().split(Regex("\\s+"))
            if (f.size < 4 || !f[0].endsWith(":")) continue
            rows[f[3]] = longArrayOf(f[1].toLong(), f[2].toLong())
        }
        rows
    } catch (_: Exception) { null }
}

internal actual fun footprint(a: IdleCores.Pair, b: IdleCores.Pair, out: (String) -> Unit) {
    Footprint.report("server core", a.server, out, shared = b.server)
    Footprint.report("client core", a.client, out, shared = b.client)
}

internal actual fun inventory(label: String, a: Any, b: Any, out: (String) -> Unit) = Footprint.report(label, a, out, shared = b)
