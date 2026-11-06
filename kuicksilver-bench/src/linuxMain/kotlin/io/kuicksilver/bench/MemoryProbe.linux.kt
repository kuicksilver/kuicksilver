// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.bench

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.toKString
import platform.posix.fclose
import platform.posix.fgets
import platform.posix.fopen

/** VmRSS from /proc/self/status. */
internal actual fun residentBytes(): Long {
    val f = fopen("/proc/self/status", "r") ?: return -1
    try {
        memScoped {
            val line = allocArray<ByteVar>(256)
            while (fgets(line, 256, f) != null) {
                val s = line.toKString()
                if (s.startsWith("VmRSS:")) return (s.removePrefix("VmRSS:").trim().split(' ').first().toLongOrNull() ?: return -1) * 1024
            }
        }
    } finally {
        fclose(f)
    }
    return -1
}

/** Not measured on Linux (glibc's mallinfo2 is not in the platform bindings). */
internal actual fun cHeapInUseBytes(): Long = -1
