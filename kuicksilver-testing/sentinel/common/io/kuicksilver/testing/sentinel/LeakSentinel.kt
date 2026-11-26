// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing.sentinel

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.LeakRegistry
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.ComparableTimeMark
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * The leak sentinel (docs/process.md, "The leak sentinel"): compiled into every module's tests (the build copies these
 * sources into each test source set), it runs around each test and each test class on every platform, through the JUnit
 * extension on the JVM, the runner builder on Android devices and the wrapped test suites on Kotlin/Native. A test must
 * leave nothing open that the library owns: no object it opened that [LeakRegistry] still lists, no more of ksl's native
 * TLS sessions, keys, session references, UDP sockets and wake descriptors than before it.
 *
 * Teardown is often asynchronous (a client's close returns before its connections end), so [end] waits for it: woken by
 * every close the registry sees and every native free, bounded by [wait]; only what is still open at the bound is a leak.
 * A class named `per-class` in [LeakAllowlist] is checked once after all its tests (fixtures shared across its tests); an
 * `allow` entry tolerates the kinds it names, with a reason, until the fix it names lands.
 */
@OptIn(InternalKuicksilverApi::class)
internal object LeakSentinel {
    /** The ksl counters a test must give back: the ones a connection or a socket makes and frees itself. Contexts and private keys are cached across tests. */
    private val nativeKinds =
        listOf(
            KslConst.LIVE_SSL to "ksl.ssl",
            KslConst.LIVE_KEY to "ksl.key",
            KslConst.LIVE_SESSION to "ksl.session",
            KslConst.LIVE_UDP to "ksl.udp",
            KslConst.LIVE_WAKE to "ksl.wake",
        )

    /** How long [end] waits for teardown; `KUICKSILVER_LEAK_WAIT_MS` changes it. */
    var wait: Duration = 10.seconds

    /** Teardown that takes longer than this is reported as slow; `KUICKSILVER_LEAK_SLOW_MS` changes it. */
    var slow: Duration = 1500.milliseconds

    /** Slow teardown fails the test too (`KUICKSILVER_LEAK_STRICT=1`), instead of only being reported. */
    var strict: Boolean = false

    private val changes = Channel<Unit>(Channel.CONFLATED)

    /**
     * How much longer than 3 x its reported PTO a period may be and still be excused (RFC 9000 section 10.2: the closing and
     * draining states last 3 x PTO): the time between the core setting its deadline and the record noting it only shortens
     * the period seen, so this covers the rounding of the conversion between the core's clock and [LeakRegistry.clockForTest].
     * The check is per connection, whatever its RTT: a period from an inflated RTT sample (a starved host whose peer
     * answered late: a 500 ms sample makes a PTO of 1.5 s and a 4.5 s period) is excused, one of 6 x PTO or from a doubled
     * PTO is not. Above that, no period longer than the sentinel's own wait bound is excused (a runaway PTO).
     */
    val PERIOD_TOLERANCE: Duration = 10.milliseconds

    /** The TLS sessions a closing QUIC connection holds: its own. */
    const val SSL_PER_PERIOD = 1

    /**
     * The packet protectors a closing QUIC connection may hold: Initial, Handshake and 1-RTT read and write keys, the original
     * Initial read key, the next and previous 1-RTT generations and the header protection keys of the 1-RTT key phase.
     */
    const val KEYS_PER_PERIOD = 16

    /**
     * Turns the registry on (once per process); [sites]: each object keeps the stack that opened it; [slowMs] and [strict]:
     * see [slow] and [strict].
     */
    fun install(
        sites: Boolean,
        waitMs: Long?,
        slowMs: Long? = null,
        strict: Boolean = false,
    ) {
        if (waitMs != null) wait = waitMs.milliseconds
        if (slowMs != null) slow = slowMs.milliseconds
        this.strict = strict
        if (!LeakRegistry.enabled) LeakRegistry.enable(sites)
        LeakRegistry.onChange { changes.trySend(Unit) }
    }

    /** What was open when a test or a class started, and how much [shared] had made by then. */
    class Scope internal constructor(
        val mark: Long,
        val native: LongArray?,
        val sharedNative: LongArray,
    )

    /**
     * The start of a test or a class: the process's caches are emptied first, so what an earlier test left there and
     * frees during this one cannot hide a native object this one leaks.
     */
    fun begin(): Scope {
        runBlocking { for (clear in LeakRegistry.processCaches()) clear() }
        return Scope(LeakRegistry.mark(), LeakRegistry.nativeObjects(), locked { sharedNative.copyOf() })
    }

    /** The native objects [shared] blocks made, per ksl counter, since the process started. Under [lock]. */
    private val sharedNative = LongArray(KslConst.LIVE_COUNT)

    /** The registry ids [shared] blocks opened. Under [lock]. */
    private val sharedIds = HashSet<Long>()

    @OptIn(ExperimentalAtomicApi::class)
    private val lock = AtomicInt(0)

    @OptIn(ExperimentalAtomicApi::class)
    private inline fun <T> locked(block: () -> T): T {
        while (!lock.compareAndSet(0, 1)) {
            // held for a copy or a few additions: spin
        }
        try {
            return block()
        } finally {
            lock.store(0)
        }
    }

    /**
     * Runs [block], which makes a fixture that lives for the whole test process (a native key cached by a fixtures
     * object, made by whichever test needs it first): what it opens is no test's leak. Any thread; what another thread
     * opens meanwhile counts as shared too.
     */
    fun <T> shared(block: () -> T): T {
        val before = LeakRegistry.nativeObjects()
        val mark = LeakRegistry.mark()
        try {
            return block()
        } finally {
            val after = LeakRegistry.nativeObjects()
            val end = LeakRegistry.mark()
            val opened = LeakRegistry.openSince(mark).filter { it.id < end }.map { it.id }
            locked {
                if (after != null) for (i in sharedNative.indices) sharedNative[i] += after[i] - (before?.get(i) ?: 0L)
                sharedIds += opened
            }
        }
    }

    /** Whether the tests of [className] are checked per class only (a `per-class` entry). */
    fun perClass(className: String): Boolean = LeakAllowlist.entries.any { it.mode == "per-class" && it.target == className }

    /**
     * What [scope] left open, once teardown settled or [wait] passed: null when nothing, else the failure message naming
     * each kind, its count and (with sites) where each object was opened. [test] is `Class.method`, or the class name for a
     * class's check.
     *
     * Teardown longer than [slow] is reported (and fails with [strict]), except the wait for a closing period the protocol
     * requires ([LeakRegistry.closing]: a QUIC connection's closing or draining state, 3 x PTO, RFC 9000 section 10.2, about
     * 3 s before its first RTT sample). Each object that closed later than [slow] after the test is judged on its own
     * ([LeakRegistry.takeClosed]: also one opened and closed between two looks): it passes only when it noted its period
     * within [slow], the period is at most 3 x the PTO it was set from ([PERIOD_TOLERANCE]) and at most [wait] long, and it
     * closed within [slow] of the period's end (plus how late its own deadline timer ran, when that ended it: a held-up loop). ksl's counters
     * belong to no object: after [slow] only `ksl.ssl` and `ksl.key` are excused, at most [SSL_PER_PERIOD] and
     * [KEYS_PER_PERIOD] per object in its period at that look (a closing QUIC connection keeps its TLS session and keys to
     * repeat its CONNECTION_CLOSE; a draining one frees them at once), never `ksl.udp`, `ksl.wake` or `ksl.session`.
     * Marks on another clock than [LeakRegistry.clockForTest] excuse nothing. It fails closed: an object a look saw whose
     * close was not logged makes the teardown slow, since nothing tells when it closed. Time over [slow] after every close
     * and free was accounted for is the sentinel's own looks (each empties the process caches) and is not slow.
     */
    fun end(
        scope: Scope,
        className: String,
        test: String?,
        allow: List<LeakAllowEntry> = LeakAllowlist.entries,
        wait: Duration = this.wait,
        slow: Duration = this.slow,
        strict: Boolean = this.strict,
        /** Called once the first look found something open (the sentinel's own negative controls). */
        afterFirstLookForTest: (() -> Unit)? = null,
        /** Called after each look at what is open, with its number from 0 (the sentinel's own tests step their teardown). */
        afterLookForTest: ((Int) -> Unit)? = null,
    ): String? {
        val allowed = allowedKinds(allow, className, test)
        val where = if (test == null) className else "$className.$test"
        val clock = LeakRegistry.clockForTest
        LeakRegistry.logCloses(true) // from now on: what closed before the wait began is not timed
        val started = clock.markNow()
        var first: List<Leak> = emptyList()
        // natives: whether the last look found ksl counters a period does not excuse, and the first look after that found
        // none (every native free wakes a look)
        var nativesBad = false
        var nativesBadUntil = Duration.ZERO
        var looks = 0
        // every registry object a look found open: each must have a logged close once teardown took longer than [slow]
        val seen = HashSet<Long>()

        fun look(left: List<Leak>) {
            val elapsed = started.elapsedNow()
            for (l in left) seen += l.ids
            val periods = left.sumOf { l -> l.closing.count { it != null } }
            val bad =
                left.any { l ->
                    l.native &&
                        when (l.kind) {
                            "ksl.ssl" -> l.count > SSL_PER_PERIOD * periods
                            "ksl.key" -> l.count > KEYS_PER_PERIOD * periods
                            else -> true
                        }
                }
            if (bad || nativesBad) nativesBadUntil = elapsed
            nativesBad = bad
            afterLookForTest?.invoke(looks++)
        }
        val loggedCloses: List<LeakRegistry.Closed>
        val left =
            try {
                runBlocking {
                    var left = settledLeftOpen(scope, allowed)
                    first = left
                    look(left)
                    if (left.isNotEmpty()) {
                        afterFirstLookForTest?.invoke()
                        withTimeoutOrNull(wait) {
                            while (true) {
                                changes.receive()
                                left = settledLeftOpen(scope, allowed)
                                look(left)
                                if (left.isEmpty()) break
                            }
                        }
                        left = settledLeftOpen(scope, allowed)
                        look(left)
                    }
                    left
                }
            } finally {
                loggedCloses = LeakRegistry.takeClosed()
                LeakRegistry.logCloses(false)
            }
        val shared = locked { sharedIds.toSet() }
        val closed =
            loggedCloses.filter {
                it.id >= scope.mark && it.id !in shared && "*" !in allowed && it.kind !in allowed
            }
        freedBefore(scope)?.let { println("leak sentinel: $where $it") }
        if (left.isNotEmpty()) return message(where, left, wait)
        val took = started.elapsedNow()
        if (first.isEmpty() || took <= slow) return null
        val kinds = first.joinToString(", ") { "${it.kind} x${it.count}" }
        val late = closed.filter { after(it.closedAt, started, slow) }
        val unexcused = late.mapNotNull { e -> unexcusedBecause(e, started, slow, wait)?.let { e to it } }
        // fails closed: an object a look saw whose close was not logged (logging was cut short) has no known close time,
        // so nothing explains the time and it counts as slow
        val unlogged = seen - closed.map { it.id }.toSet()
        if (unexcused.isEmpty() && unlogged.isEmpty() && nativesBadUntil <= slow) {
            // every close and free is accounted for: the time over the bound was waiting for closing periods, or the
            // sentinel's own looks (each empties the process caches first), which are no teardown
            val waitedFor =
                if (late.isEmpty()) {
                    "every object closed within ${slow.inWholeMilliseconds} ms (the rest was the sentinel's own looks)"
                } else {
                    // a period whose deadline timer ran late names that lateness: a loop stall shows in the log
                    val periods =
                        late.joinToString(", ") { e ->
                            e.kind + (e.periodLateBy?.let { ", timer ${it.inWholeMilliseconds} ms late" } ?: "")
                        }
                    "waiting for closing periods (RFC 9000 section 10.2) of $periods"
                }
            println("leak sentinel: $where took ${took.inWholeMilliseconds} ms to close $kinds, $waitedFor: not slow")
            return null
        }
        val why =
            buildList {
                for ((k, list) in unexcused.groupBy { it.first.kind }) {
                    val reasons = list.map { it.second }.distinct().joinToString(", ")
                    add("$k x${list.size} closed after ${slow.inWholeMilliseconds} ms ($reasons)")
                }
                if (unlogged.isNotEmpty()) {
                    add("${unlogged.size} object(s) closed without a logged close: nothing logged explains ${took.inWholeMilliseconds} ms")
                }
                if (nativesBadUntil > slow) add("ksl counters until ${nativesBadUntil.inWholeMilliseconds} ms")
            }.joinToString("; ")
        val note =
            "leak sentinel: $where took ${took.inWholeMilliseconds} ms to close $kinds (more than ${slow.inWholeMilliseconds} ms: $why)"
        println(note)
        return if (strict) "$note; KUICKSILVER_LEAK_STRICT fails slow teardown" else null
    }

    /** Whether [mark] is more than [slow] after [started]; a mark of another clock counts as late (nothing excuses it). */
    private fun after(
        mark: ComparableTimeMark,
        started: ComparableTimeMark,
        slow: Duration,
    ): Boolean =
        try {
            mark - started > slow
        } catch (_: IllegalArgumentException) {
            true
        }

    /**
     * Why [e], which closed late, did not just wait out a closing period, or null when it did: noted within [slow] of
     * [started], at most 3 x the PTO it was set from ([PERIOD_TOLERANCE]) and at most [ceiling] long, and closed within
     * [slow] of its end, plus how late its own deadline timer ran when that ended it (a held-up loop: GC, a starved host;
     * [LeakRegistry.Closed.periodLateBy], at most [ceiling]). Marks of different clocks excuse nothing.
     */
    private fun unexcusedBecause(
        e: LeakRegistry.Closed,
        started: ComparableTimeMark,
        slow: Duration,
        ceiling: Duration,
    ): String? {
        val until = e.closingUntil ?: return "no closing period"
        val noted = e.closingNoted ?: return "no closing period"
        val pto = e.closingPto ?: return "a period without its PTO"
        val ms = { d: Duration -> "${d.inWholeMilliseconds} ms" }
        return try {
            val period = until - noted
            // the loop's own lateness in running the period's deadline (a held-up loop) is no longer period, up to the wait
            val lateTimer = (e.periodLateBy ?: Duration.ZERO).coerceAtMost(ceiling)
            val timerNote = e.periodLateBy?.let { ", its timer ${ms(it)} late" } ?: ""
            when {
                noted - started > slow -> "its period began ${ms(noted - started)} after the test"
                period > pto * 3 + PERIOD_TOLERANCE -> "a period of ${ms(period)}, more than 3 x its PTO of ${ms(pto)}"
                period > ceiling -> "a period of ${ms(period)}, longer than the ${ms(ceiling)} wait"
                e.closedAt - until > slow + lateTimer -> "closed ${ms(e.closedAt - until)} after its period$timerNote"
                else -> null
            }
        } catch (_: IllegalArgumentException) {
            "marks of another clock"
        }
    }

    /**
     * The ksl counters that ended below where they were when [scope] began: the test freed native objects it did not make
     * (an earlier test's, or a fixture's). Not a failure, but such a drop can hide a leak of the same kind, so it is said.
     */
    fun freedBefore(scope: Scope): String? {
        val before = scope.native ?: return null
        val now = LeakRegistry.nativeObjects() ?: return null
        val shared = locked { sharedNative.copyOf() }
        val drops =
            nativeKinds.mapNotNull { (i, kind) ->
                val delta = now[i] - before[i] - (shared[i] - scope.sharedNative[i])
                if (delta < 0) "$kind $delta" else null
            }
        return if (drops.isEmpty()) null else "freed ksl objects it did not make: ${drops.joinToString(", ")}"
    }

    /** One leaked kind: how many, and where each was opened (when the registry keeps sites). */
    class Leak(
        val kind: String,
        val count: Long,
        val sites: List<String>,
        /** Per registry object, the end of its closing period ([LeakRegistry.closing]), null outside one; empty for ksl's counters. */
        val closing: List<ComparableTimeMark?> = emptyList(),
        /** One of ksl's counters, not registry objects. */
        val native: Boolean = false,
        /** The registry ids of the objects (empty for ksl's counters). */
        val ids: List<Long> = emptyList(),
    )

    /** [leftOpen] once the process's caches were emptied (a connection that ends late may still store its session there). */
    private suspend fun settledLeftOpen(
        scope: Scope,
        allowed: Set<String>,
    ): List<Leak> {
        for (clear in LeakRegistry.processCaches()) clear()
        return leftOpen(scope, allowed)
    }

    private fun leftOpen(
        scope: Scope,
        allowed: Set<String>,
    ): List<Leak> {
        val out = ArrayList<Leak>()
        val sharedNow = locked { sharedIds.toSet() to sharedNative.copyOf() }
        for ((kind, entries) in LeakRegistry.openSince(scope.mark).filter { it.id !in sharedNow.first }.groupBy { it.kind }) {
            if ("*" in allowed || kind in allowed) continue
            out +=
                Leak(
                    kind,
                    entries.size.toLong(),
                    entries.mapNotNull { it.site },
                    entries.map { it.closingUntil },
                    ids = entries.map { it.id },
                )
        }
        val before = scope.native
        val now = if (before != null) LeakRegistry.nativeObjects() else null
        if (before != null && now != null) {
            for ((i, kind) in nativeKinds) {
                val more = now[i] - before[i] - (sharedNow.second[i] - scope.sharedNative[i])
                if (more > 0 && "*" !in allowed && kind !in allowed) out += Leak(kind, more, emptyList(), native = true)
            }
        }
        return out
    }

    /**
     * The kinds the `allow` entries of [className] tolerate: those naming the class, and those naming [test]; for the class's
     * own check ([test] null) those naming any of its tests too, since what a test may leave is still there at the class's end.
     */
    private fun allowedKinds(
        allow: List<LeakAllowEntry>,
        className: String,
        test: String?,
    ): Set<String> =
        allow
            .filter {
                it.mode == "allow" &&
                    (
                        it.target == className ||
                            (if (test == null) it.target.startsWith("$className.") else it.target == "$className.$test")
                    )
            }.flatMap { it.kinds }
            .toSet()

    private fun message(
        where: String,
        left: List<Leak>,
        wait: Duration,
    ): String =
        buildString {
            append("leak sentinel: ")
                .append(where)
                .append(" left open after ")
                .append(wait)
                .append(": ")
            append(left.joinToString(", ") { "${it.kind} x${it.count}" })
            val sites = left.filter { it.sites.isNotEmpty() }
            if (sites.isEmpty()) {
                append(" (KUICKSILVER_LEAK_SITES=1 records where each was opened)")
            } else {
                for (l in sites) for (s in l.sites) append("\n  ").append(l.kind).append(" opened at:\n").append(s)
            }
        }
}

/** A line of tools/check/sentinel.allow: [mode] `allow` (with [kinds]) or `per-class`, its [target] class or test. */
internal class LeakAllowEntry(
    val mode: String,
    val target: String,
    val kinds: List<String>,
)
