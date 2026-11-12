// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    kotlinx.coroutines.DelicateCoroutinesApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
    kotlin.concurrent.atomics.ExperimentalAtomicApi::class,
)

package io.kuicksilver.ktor.client.pac

import io.kuicksilver.ktor.client.h1.monotonicMillis
import kotlinx.coroutines.CloseableCoroutineDispatcher
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicLong

/**
 * Runs PAC scripts on one thread of their own, each in its [PacContext] (kept per script source, at most [MAX_CONTEXTS],
 * the least recently used released). A run's time limit counts from when it starts on that thread, not from when it was
 * queued behind others. JavaScriptCore's public API cannot interrupt a script, so a run that overruns its limit gives no
 * answer and its thread is abandoned to it: the next run gets a new thread and new contexts. While [MAX_ABANDONED]
 * threads are abandoned no script runs (lookups give no answer, so the next setting or a direct connection); when an
 * abandoned run ends its thread and contexts are released and scripts run again. A hostile script can so hold at most
 * [MAX_ABANDONED] threads at a time. The DNS lookups a script makes are bounded by its run's limit ([PacRun]).
 */
internal object PacRunner {
    const val MAX_CONTEXTS: Int = 8
    const val MAX_ABANDONED: Int = 2
    private const val IDLE = Long.MIN_VALUE

    private class Worker(
        val dispatcher: CloseableCoroutineDispatcher,
    ) {
        /** Source key → (script, its context); touched only on [dispatcher]'s thread. */
        val contexts = LinkedHashMap<String, Pair<String, PacContext>>()

        /** When the run now on the thread started; [IDLE] when none runs. */
        val busySince = AtomicLong(IDLE)

        fun find(
            key: String,
            script: String,
            url: String,
            host: String,
        ): String {
            val held = contexts.remove(key)
            val ctx =
                if (held != null && held.first == script) {
                    held.second
                } else {
                    held?.second?.close()
                    PacContext(script)
                }
            contexts[key] = script to ctx
            while (contexts.size > MAX_CONTEXTS) contexts.remove(contexts.keys.first())?.second?.close()
            return ctx.findProxy(url, host)
        }

        fun releaseContexts() {
            for ((_, c) in contexts.values) c.close()
            contexts.clear()
        }
    }

    private val lock = Mutex()
    private var worker: Worker? = null
    private val abandonedCount = MutableStateFlow(0)
    private val clock = monotonicMillis()

    /** Tests: replaces the clock reading; null for the real one. */
    var nowForTest: (() -> Long)? = null

    internal fun now(): Long = nowForTest?.invoke() ?: clock()

    /** Threads now abandoned to runs that overran their limit (tests). */
    val abandonedThreads: StateFlow<Int> get() = abandonedCount

    /**
     * `FindProxyForURL([url], [host])` of [script] (cached under [key]), or null when the script cannot be loaded, throws,
     * answers no string, or runs longer than [limitMillis] once it started. The wait for its turn is bounded by the
     * caller (a cancellation then gives up the queued run).
     */
    suspend fun findProxy(
        key: String,
        script: String,
        url: String,
        host: String,
        limitMillis: Long,
    ): String? {
        val w =
            lock.withLock {
                // a run that overran while its caller was cancelled (no accounting then) is found here
                worker?.let { cur ->
                    val since = cur.busySince.load()
                    if (since != IDLE && now() - since > limitMillis) abandon(cur)
                }
                if (abandonedCount.value >= MAX_ABANDONED) return null
                worker ?: Worker(newSingleThreadContext("kuicksilver-pac")).also { worker = it }
            }
        val started = CompletableDeferred<Long>()
        val call =
            GlobalScope.async(w.dispatcher) {
                val at = now()
                w.busySince.store(at)
                started.complete(at)
                try {
                    PacRun.begin(at + limitMillis * 3 / 4)
                    runCatching { w.find(key, script, url, host) }
                } finally {
                    PacRun.end()
                    w.busySince.store(IDLE)
                }
            }
        var answer: Result<String>? = null
        try {
            started.await()
            answer = withTimeoutOrNull(limitMillis) { call.await() }
            return answer?.getOrNull()
        } finally {
            if (answer == null) {
                call.cancel() // a run not started yet never starts; one under way ends on its own
                val since = if (started.isCompleted) started.getCompleted() else null
                if (since != null && !call.isCompleted && now() - since >= limitMillis) {
                    withContext(NonCancellable) { lock.withLock { abandon(w) } }
                }
            }
        }
    }

    /** Gives [w]'s thread up to the run on it; under [lock]. When that run ends the thread and its contexts go. */
    private fun abandon(w: Worker) {
        if (worker !== w) return
        worker = null
        abandonedCount.update { it + 1 }
        GlobalScope
            .launch(w.dispatcher) {
                // queued behind the overrunning run: it runs once that run ended, on the same thread
                w.releaseContexts()
            }.invokeOnCompletion {
                abandonedCount.update { it - 1 }
                GlobalScope.launch(Dispatchers.Default) { w.dispatcher.close() }
            }
    }

    /** Tests: wait until no thread is abandoned. */
    suspend fun awaitNoneAbandoned() {
        abandonedCount.first { it == 0 }
    }
}

/**
 * The run under way on the PAC thread: the deadline of its DNS lookups and their answers, so a script that resolves
 * the same name again gets it at once. Touched only on that thread.
 */
@kotlin.native.concurrent.ThreadLocal
internal object PacRun {
    var deadline: Long = 0
        private set
    val answers = HashMap<Pair<String, Boolean>, List<String>>()

    fun begin(deadlineMillis: Long) {
        deadline = deadlineMillis
        answers.clear()
    }

    fun end() {
        deadline = 0
        answers.clear()
    }

    /** What remains of the run's DNS budget, in milliseconds (0 outside a run). */
    fun remaining(): Long = if (deadline == 0L) 0 else (deadline - PacRunner.now()).coerceAtLeast(0)
}
