// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlin.native.runtime.NativeRuntimeApi::class, ExperimentalStdlibApi::class)

package io.kuicksilver.soak

import kotlinx.cinterop.toKString
import kotlin.native.runtime.GC

internal actual object ProcessResources {
    actual fun sample(): Map<String, Long> {
        GC.collect()
        val out = LinkedHashMap<String, Long>()
        out["proc.rssKiB"] = rssKiB()
        out["proc.fds"] = openFds()
        out["kn.heapAfterGcKiB"] = (
            GC.lastGCInfo
                ?.memoryUsageAfter
                ?.get("heap")
                ?.totalObjectsSizeBytes ?: -1024L
        ) / 1024
        return out
    }

    actual fun env(name: String): String? = platform.posix.getenv(name)?.toKString()
}

/** Resident set size in KiB, -1 when the platform does not tell. */
internal expect fun rssKiB(): Long

/** Open file descriptors, -1 when the platform does not tell. */
internal expect fun openFds(): Long
