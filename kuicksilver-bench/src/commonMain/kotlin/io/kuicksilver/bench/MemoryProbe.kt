// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.bench

/**
 * What this process holds and allocates, per platform, for [MemoryBench]. Every heap figure is taken after a full collection,
 * so it is live data, not garbage.
 */
internal expect object MemoryProbe {
    /** The runtime's name for the report: "JVM" or "Native". */
    val runtime: String

    /** Live objects on the managed heap after a full collection (JVM: heap used; Kotlin/Native: the collector's object bytes), in bytes. */
    fun liveHeapBytes(): Long

    /** The resident set of the process in bytes, -1 when the platform does not tell. */
    fun rssBytes(): Long

    /** Bytes the C allocator has handed out and not taken back (OpenSSL's objects live there), -1 when the platform does not tell. */
    fun mallocInUseBytes(): Long

    /**
     * Starts counting managed-heap allocations of the whole process. [AllocationCounter.tick] is to be called at least every few
     * MiB of work (Kotlin/Native counts by forcing a collection there; the JVM reads its per-thread counters and ignores ticks).
     */
    fun allocationCounter(): AllocationCounter

    /** Per-class live instances and bytes after a full collection, or null where the runtime does not tell (only the JVM does). */
    fun classHistogram(): Map<String, LongArray>?
}

/** See [MemoryProbe.allocationCounter]. */
internal interface AllocationCounter {
    fun tick()

    /** Bytes allocated since the counter started. */
    fun allocated(): Long

    /** A note on how exact [allocated] is (Kotlin/Native: collections the counter did not force and so could not see), or null. */
    fun caveat(): String?
}
