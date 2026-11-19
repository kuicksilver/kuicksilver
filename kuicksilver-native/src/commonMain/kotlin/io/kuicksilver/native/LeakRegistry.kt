// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The library-owned objects alive now, for the test harness's leak sentinel (docs/process.md, "The leak sentinel"): QUIC
 * endpoints and connections, HTTP/3 sessions, requests, WebTransport sessions and datagram flows, HTTP/2 and HTTP/1
 * connections and pools, TLS connections, sockets and the coroutine scopes the library owns. An owner calls [open] when it
 * is made and [close] with the id it got once it released everything; the sentinel lists what a test opened and left open.
 *
 * Off by default, and off in production: [open] then returns 0 after one volatile read and [close] of 0 returns at once,
 * so an owner pays a read and a `Long` field. Only objects opened after [enable] are tracked. With `sites`, each entry also
 * keeps the stack that opened it (a debugging aid: a stack per object is far too costly for every run).
 */
@InternalKuicksilverApi
@OptIn(ExperimentalAtomicApi::class)
public object LeakRegistry {
    /** One object alive: what it is ([kind], e.g. `quic.connection`), its [id] and, when sites are kept, where it was opened. */
    public class Entry internal constructor(
        public val id: Long,
        public val kind: String,
        public val site: String?,
    )

    @Volatile private var on = false

    @Volatile private var withSites = false

    @Volatile private var listener: (() -> Unit)? = null

    private val ids = AtomicLong(1)
    private val lock = AtomicInt(0)
    private val live = HashMap<Long, Entry>()

    /** Whether owners are tracked now. */
    public val enabled: Boolean get() = on

    /** Tracks every object opened from now on; [sites]: each keeps the stack that opened it. */
    public fun enable(sites: Boolean) {
        withSites = sites
        on = true
    }

    /**
     * An owner of [kind] was made: the id to [close] it with, 0 when tracking is off. Never throws; any thread.
     */
    public fun open(kind: String): Long = if (!on) 0L else register(kind)

    private fun register(kind: String): Long {
        val id = ids.fetchAndAdd(1L)
        val site = if (withSites) site() else null
        locked { live[id] = Entry(id, kind, site) }
        return id
    }

    /** The owner [open] answered [id] released everything; 0 and a second close do nothing. Never throws; any thread. */
    public fun close(id: Long) {
        if (id == 0L) return
        if (locked { live.remove(id) } != null) listener?.invoke()
    }

    /** A native object was freed (ksl's live counters fell): wakes a sentinel waiting for teardown. */
    public fun nativeFreed() {
        listener?.invoke()
    }

    private val caches = AtomicReference<List<suspend () -> Unit>>(emptyList())

    /**
     * A cache that lives for the whole process ([clear] empties it) holds native objects on behalf of no one in particular
     * (the default TLS session cache): the sentinel empties it before it counts, so what a test's connections left there
     * is not taken for the test's leak. Does nothing while tracking is off.
     */
    public fun processCache(clear: suspend () -> Unit) {
        if (!on) return
        while (true) {
            val l = caches.load()
            if (caches.compareAndSet(l, l + clear)) return
        }
    }

    /** The [processCache]s registered so far. */
    public fun processCaches(): List<suspend () -> Unit> = caches.load()

    /** Ids from now on are at least this: [openSince] of it lists what is opened later. */
    public fun mark(): Long = ids.load()

    /** The objects opened at or after [mark] that are still open, oldest first. */
    public fun openSince(mark: Long): List<Entry> = locked { live.values.filter { it.id >= mark } }.sortedBy { it.id }

    /** Called (on any thread) after every [close] and native free while set: the sentinel's wake-up. */
    public fun onChange(l: (() -> Unit)?) {
        listener = l
    }

    /**
     * ksl's live-object counters ([Ksl.liveObjects]) when the native library is already loaded, else null: reading them
     * never loads it (a test of the loader decides when that happens).
     */
    public fun nativeObjects(): LongArray? = if (kslLoaded()) Ksl.liveObjects() else null

    private inline fun <T> locked(block: () -> T): T {
        while (!lock.compareAndSet(0, 1)) {
            // held for one map operation: spin
        }
        try {
            return block()
        } finally {
            lock.store(0)
        }
    }

    /** The opener's frames: the stack without this object's own and the runtime's first lines, at most 16 of them. */
    private fun site(): String =
        Throwable()
            .stackTraceToString()
            .lineSequence()
            .drop(1)
            .map { it.trim() }
            .filter { it.isNotEmpty() && "LeakRegistry" !in it }
            .take(16)
            .joinToString("\n") { "    $it" }
}

/** Whether the native library was loaded in this process already (always on Kotlin/Native, where it is linked in). */
internal expect fun kslLoaded(): Boolean
