// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.native.runtime.NativeRuntimeApi::class, ExperimentalStdlibApi::class)

package io.kuicksilver.bench

import kotlin.native.runtime.GC

internal actual object MemoryProbe {
    actual val runtime: String = "Native"

    actual fun liveHeapBytes(): Long {
        // twice: the default allocator sweeps after a collection returns, so the first one's figure can still count garbage
        GC.collect()
        GC.collect()
        return GC.lastGCInfo?.memoryUsageAfter?.get("heap")?.totalObjectsSizeBytes ?: -1
    }

    actual fun rssBytes(): Long = residentBytes()

    actual fun mallocInUseBytes(): Long = cHeapInUseBytes()

    /**
     * The collector keeps no running total, so every [AllocationCounter.tick] forces a collection and adds what the heap
     * held before it minus what it held after the previous one. A collection the counter did not force (the collector's own
     * schedule) hides what was allocated before it; [AllocationCounter.caveat] says how many there were, and then the figure
     * is a lower bound.
     */
    actual fun allocationCounter(): AllocationCounter = object : AllocationCounter {
        private var total = 0L
        private var missed = 0L
        private var lastAfter: Long
        private var lastEpoch: Long

        init {
            GC.collect()
            val info = GC.lastGCInfo!!
            lastAfter = info.memoryUsageAfter["heap"]!!.totalObjectsSizeBytes
            lastEpoch = info.epoch
        }

        override fun tick() {
            GC.collect()
            val info = GC.lastGCInfo!!
            missed += info.epoch - lastEpoch - 1
            total += info.memoryUsageBefore["heap"]!!.totalObjectsSizeBytes - lastAfter
            lastAfter = info.memoryUsageAfter["heap"]!!.totalObjectsSizeBytes
            lastEpoch = info.epoch
        }

        override fun allocated(): Long = total

        override fun caveat(): String? = if (missed == 0L) null else "a lower bound: $missed collections ran between ticks"
    }

    actual fun classHistogram(): Map<String, LongArray>? = null
}

internal actual fun footprint(a: IdleCores.Pair, b: IdleCores.Pair, out: (String) -> Unit) = Unit

internal actual fun inventory(label: String, a: Any, b: Any, out: (String) -> Unit) = Unit

/** The resident set in bytes, -1 when the platform does not tell. */
internal expect fun residentBytes(): Long

/** The C allocator's bytes in use, -1 when the platform does not tell. */
internal expect fun cHeapInUseBytes(): Long

/** `memory [connections] [transferMiB] [section...]`: [MemoryBench] on Kotlin/Native (`./gradlew :kuicksilver-bench:runMemoryReleaseExecutableMacosArm64`). */
public fun memoryMain(args: Array<String>) {
    kotlinx.coroutines.runBlocking { MemoryBench.run(args.getOrNull(0)?.toInt() ?: 1000, args.getOrNull(1)?.toInt() ?: 256, args.drop(2).toSet().ifEmpty { MemoryBench.sections.toSet() }) }
}
