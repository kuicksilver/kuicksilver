// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.soak

import java.io.File
import java.lang.management.BufferPoolMXBean
import java.lang.management.ManagementFactory

internal actual object ProcessResources {
    actual fun sample(): Map<String, Long> {
        System.gc()
        System.gc() // the second pass also collects what the first one's finalization released
        val out = LinkedHashMap<String, Long>()
        out["proc.rssKiB"] = rssKiB()
        val os = ManagementFactory.getOperatingSystemMXBean()
        out["proc.fds"] = (os as? com.sun.management.UnixOperatingSystemMXBean)?.openFileDescriptorCount ?: -1L
        out["jvm.heapAfterGcKiB"] = ManagementFactory.getMemoryMXBean().heapMemoryUsage.used / 1024
        val direct = ManagementFactory.getPlatformMXBeans(BufferPoolMXBean::class.java).firstOrNull { it.name == "direct" }
        out["jvm.directKiB"] = (direct?.memoryUsed ?: 0L) / 1024
        out["jvm.directBuffers"] = direct?.count ?: 0L
        out["jvm.threads"] = ManagementFactory.getThreadMXBean().threadCount.toLong()
        return out
    }

    /** VmRSS from /proc on Linux; `ps` elsewhere (macOS has no /proc and the JDK exposes no resident size). */
    private fun rssKiB(): Long {
        val status = File("/proc/self/status")
        if (status.exists()) {
            return status
                .readLines()
                .firstOrNull { it.startsWith("VmRSS:") }
                ?.split(Regex("\\s+"))
                ?.getOrNull(1)
                ?.toLongOrNull() ?: -1L
        }
        return try {
            val p = ProcessBuilder("ps", "-o", "rss=", "-p", ProcessHandle.current().pid().toString()).redirectErrorStream(true).start()
            val text =
                p.inputStream
                    .bufferedReader()
                    .readText()
                    .trim()
            p.waitFor()
            text.toLongOrNull() ?: -1L
        } catch (_: Exception) {
            -1L
        }
    }

    actual fun env(name: String): String? = System.getenv(name)
}
