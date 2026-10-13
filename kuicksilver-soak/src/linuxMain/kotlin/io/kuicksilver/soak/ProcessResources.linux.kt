// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.soak

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.toKString
import platform.posix.closedir
import platform.posix.fclose
import platform.posix.fgets
import platform.posix.fopen
import platform.posix.opendir
import platform.posix.readdir

/** VmRSS from /proc/self/status. */
internal actual fun rssKiB(): Long {
    val f = fopen("/proc/self/status", "r") ?: return -1
    try {
        memScoped {
            val line = allocArray<ByteVar>(256)
            while (fgets(line, 256, f) != null) {
                val s = line.toKString()
                if (s.startsWith("VmRSS:")) {
                    return s
                        .removePrefix("VmRSS:")
                        .trim()
                        .substringBefore(' ')
                        .toLongOrNull() ?: -1
                }
            }
        }
    } finally {
        fclose(f)
    }
    return -1
}

/** Entries of /proc/self/fd, less ".", ".." and the descriptor of the directory stream itself. */
internal actual fun openFds(): Long {
    val d = opendir("/proc/self/fd") ?: return -1
    var n = 0L
    try {
        while (readdir(d) != null) n++
    } finally {
        closedir(d)
    }
    return n - 3
}
