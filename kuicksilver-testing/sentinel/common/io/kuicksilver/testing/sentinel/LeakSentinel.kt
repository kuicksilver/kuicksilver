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
    ): String? {
        val allowed = allowedKinds(allow, className, test)
        val where = if (test == null) className else "$className.$test"
        val started = TimeSource.Monotonic.markNow()
        var first: List<Leak> = emptyList()
        val left =
            runBlocking {
                var left = settledLeftOpen(scope, allowed)
                first = left
                if (left.isNotEmpty()) {
                    afterFirstLookForTest?.invoke()
                    withTimeoutOrNull(wait) {
                        while (true) {
                            changes.receive()
                            left = settledLeftOpen(scope, allowed)
                            if (left.isEmpty()) break
                        }
                    }
                    left = settledLeftOpen(scope, allowed)
                }
                left
            }
        freedBefore(scope)?.let { println("leak sentinel: $where $it") }
        if (left.isNotEmpty()) return message(where, left, wait)
        val took = started.elapsedNow()
        if (first.isEmpty() || took <= slow) return null
        val note =
            "leak sentinel: $where took ${took.inWholeMilliseconds} ms to close " +
                first.joinToString(", ") { "${it.kind} x${it.count}" } + " (more than ${slow.inWholeMilliseconds} ms)"
        println(note)
        return if (strict) "$note; KUICKSILVER_LEAK_STRICT fails slow teardown" else null
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
            out += Leak(kind, entries.size.toLong(), entries.mapNotNull { it.site })
        }
        val before = scope.native
        val now = if (before != null) LeakRegistry.nativeObjects() else null
        if (before != null && now != null) {
            for ((i, kind) in nativeKinds) {
                val more = now[i] - before[i] - (sharedNow.second[i] - scope.sharedNative[i])
                if (more > 0 && "*" !in allowed && kind !in allowed) out += Leak(kind, more, emptyList())
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
