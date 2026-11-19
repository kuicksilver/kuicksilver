// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.testing.sentinel

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.LeakRegistry
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

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

    private val changes = Channel<Unit>(Channel.CONFLATED)

    /** Turns the registry on (once per process); [sites]: each object keeps the stack that opened it. */
    fun install(
        sites: Boolean,
        waitMs: Long?,
    ) {
        if (waitMs != null) wait = Duration.parse("${waitMs}ms")
        if (!LeakRegistry.enabled) LeakRegistry.enable(sites)
        LeakRegistry.onChange { changes.trySend(Unit) }
    }

    /** What was open when a test or a class started, and how much [shared] had made by then. */
    class Scope internal constructor(
        val mark: Long,
        val native: LongArray?,
        val sharedNative: LongArray,
    )

    fun begin(): Scope = Scope(LeakRegistry.mark(), LeakRegistry.nativeObjects(), sharedNative.copyOf())

    /** The native objects [shared] blocks made, per ksl counter, since the process started. */
    private val sharedNative = LongArray(KslConst.LIVE_COUNT)

    /** The registry ids [shared] blocks opened. */
    private val sharedIds = HashSet<Long>()

    /**
     * Runs [block], which makes a fixture that lives for the whole test process (a native key cached by a fixtures
     * object, made by whichever test needs it first): what it opens is no test's leak. Test thread only.
     */
    fun <T> shared(block: () -> T): T {
        val before = LeakRegistry.nativeObjects()
        val mark = LeakRegistry.mark()
        try {
            return block()
        } finally {
            val after = LeakRegistry.nativeObjects()
            val end = LeakRegistry.mark()
            if (after != null) for (i in sharedNative.indices) sharedNative[i] += after[i] - (before?.get(i) ?: 0L)
            for (e in LeakRegistry.openSince(mark)) if (e.id < end) sharedIds += e.id
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
    ): String? {
        val allowed = allowedKinds(allow, className, test)
        val left =
            runBlocking {
                var left = settledLeftOpen(scope, allowed)
                if (left.isNotEmpty()) {
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
        if (left.isEmpty()) return null
        return message(if (test == null) className else "$className.$test", left, wait)
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
        for ((kind, entries) in LeakRegistry.openSince(scope.mark).filter { it.id !in sharedIds }.groupBy { it.kind }) {
            if ("*" in allowed || kind in allowed) continue
            out += Leak(kind, entries.size.toLong(), entries.mapNotNull { it.site })
        }
        val before = scope.native
        val now = if (before != null) LeakRegistry.nativeObjects() else null
        if (before != null && now != null) {
            for ((i, kind) in nativeKinds) {
                val more = now[i] - before[i] - (sharedNative[i] - scope.sharedNative[i])
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
