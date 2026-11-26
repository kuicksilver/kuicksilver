// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.native

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.TimeSource

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
    ) {
        /**
         * Set by [closing]: the object is in a closing period the protocol requires and ends by itself at this time (a QUIC
         * connection's closing or draining state, three times its PTO, RFC 9000 section 10.2); null while it is not. On
         * [clockForTest], like [closingNoted].
         */
        @Volatile public var closingUntil: ComparableTimeMark? = null
            internal set

        /** When [closing] was called for this object, null before. */
        @Volatile public var closingNoted: ComparableTimeMark? = null
            internal set

        /** The PTO [closing] said the period was set from (3 x it), null before or when it named none. */
        @Volatile public var closingPto: Duration? = null
            internal set
    }

    /** An object [close] removed while closes were logged ([logCloses]): no opening stack, only what judging its close needs. */
    public class Closed internal constructor(
        public val id: Long,
        public val kind: String,
        public val closingUntil: ComparableTimeMark?,
        public val closingNoted: ComparableTimeMark?,
        public val closingPto: Duration?,
        public val closedAt: ComparableTimeMark,
        /** How late its period's own deadline timer ran, when the period ended it ([close]); null otherwise. */
        public val periodLateBy: Duration? = null,
    )

    @Volatile private var on = false

    @Volatile private var withSites = false

    @Volatile private var listener: (() -> Unit)? = null

    private val ids = AtomicLong(1)
    private val lock = AtomicInt(0)
    private val live = HashMap<Long, Entry>()

    /** Whether owners are tracked now. */
    public val enabled: Boolean get() = on

    /** Whether [enable] asked for each object's opening stack (kept across [disable]). */
    public val sitesKept: Boolean get() = withSites

    /** Tracks every object opened from now on; [sites]: each keeps the stack that opened it. */
    public fun enable(sites: Boolean) {
        withSites = sites
        on = true
    }

    /**
     * Stops tracking objects opened from now on (those tracked already stay until closed), until the next [enable]: for
     * a measurement that must see the library as production runs it, without the completion handlers an owner registers
     * to [close] its id (the memory benchmark's per-connection inventory). Returns whether tracking was on;
     * `enable(sitesKept)` turns it back on as it was.
     */
    public fun disable(): Boolean {
        val was = on
        on = false
        return was
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

    /**
     * The clock of [Entry.closingUntil], [Entry.closingNoted] and [Closed.closedAt]: `TimeSource.Monotonic`. The sentinel's
     * own tests set a TestTimeSource and put this one back when they end; nothing else changes it.
     */
    @Volatile public var clockForTest: TimeSource.WithComparableMarks = TimeSource.Monotonic

    /** Whether [close] logs what it removes ([logCloses]); off except while a sentinel waits for teardown. */
    @Volatile private var logging = false

    /** The objects closed while [logging], newest last; at most [CLOSED_LOG] (the oldest go first). Under [lock]. */
    private val closedLog = ArrayDeque<Closed>()

    /** The owner [open] answered [id] released everything; 0 and a second close do nothing. Never throws; any thread. */
    public fun close(id: Long): Unit = close(id, null)

    /**
     * [close], for an owner whose closing period ([closing]) ended by its own deadline: [periodLateBy] is how long after that
     * deadline its timer ran, by the owner's own clock (a held-up event loop: a GC pause, a starved host). The sentinel
     * allows that lateness on top of its bound; a close by any other path names none.
     */
    public fun close(
        id: Long,
        periodLateBy: Duration?,
    ) {
        if (id == 0L) return
        val log = logging
        val at = if (log) clockForTest.markNow() else null
        val e =
            locked {
                live.remove(id)?.also {
                    if (at != null) {
                        closedLog.addLast(Closed(it.id, it.kind, it.closingUntil, it.closingNoted, it.closingPto, at, periodLateBy))
                        if (closedLog.size > CLOSED_LOG) closedLog.removeFirst()
                    }
                }
            }
        if (e != null) listener?.invoke()
    }

    /**
     * Starts ([on]) or stops logging what [close] removes, and drops what was logged: the sentinel logs while it waits for a
     * test's teardown, so each object that closed meanwhile is judged on its own, also one opened and closed between two of
     * its looks ([takeClosed]). Starting while logging already throws IllegalStateException: one sentinel at a time.
     */
    public fun logCloses(on: Boolean) {
        locked {
            // one sentinel at a time: a second one would take or end the other's log
            check(!(on && logging)) { "closes are logged already: another sentinel is waiting" }
            closedLog.clear()
            logging = on
        }
    }

    /** The objects closed since logging started or since the last call, oldest first, and forgets them. */
    public fun takeClosed(): List<Closed> = locked { closedLog.toList().also { closedLog.clear() } }

    /**
     * The owner [open] answered [id] entered a closing period the protocol requires (RFC 9000 section 10.2: a QUIC connection
     * that sent or received CONNECTION_CLOSE stays for three times its PTO, about 3 s before its first RTT sample) that ends
     * by itself [left] from now, a period set as 3 x [pto] (null: no PTO to check it against, which excuses nothing): the
     * sentinel does not take the wait for it for slow teardown when it is no longer than the RFC allows (see
     * `LeakSentinel.end`). The end is set on [clockForTest] (`TimeSource.Monotonic`). A QUIC connection reports its period once:
     * draining after closing keeps the closing state's end (RFC 9000 section 10.2.2). Another call sets both the end and
     * the time it was noted anew. 0 and an id already closed do nothing. Wakes a sentinel waiting for teardown. Never throws;
     * any thread.
     */
    public fun closing(
        id: Long,
        left: Duration,
        pto: Duration?,
    ) {
        if (id == 0L) return
        val now = clockForTest.markNow()
        val e = locked { live[id] } ?: return
        e.closingPto = pto
        e.closingNoted = now
        e.closingUntil = now + left
        listener?.invoke()
    }

    /** A native object was freed (ksl's live counters fell): wakes a sentinel waiting for teardown. */
    public fun nativeFreed() {
        listener?.invoke()
    }

    private val caches = AtomicReference<List<suspend () -> Unit>>(emptyList())

    /**
     * A cache that lives for the whole process ([clear] empties it) holds native objects on behalf of no one in particular
     * (the default TLS session cache): the sentinel empties it before it counts, so what a test's connections left there
     * is not taken for the test's leak. Registered whether tracking is on or not, so a cache made before [enable] (a class
     * initialized early) is not missed: one list entry per such cache, made once per process.
     */
    public fun processCache(clear: suspend () -> Unit) {
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

    /** The most closed objects [takeClosed] hands over at once: far more than a test closes after it returned. */
    private const val CLOSED_LOG = 100_000

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
