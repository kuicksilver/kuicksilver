// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.client.pac

import kotlinx.coroutines.CloseableCoroutineDispatcher
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.newSingleThreadContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.AtomicInt

/**
 * Runs PAC scripts on one thread of their own, each in its [PacContext] (kept per script source, at most [MAX_CONTEXTS],
 * the least recently used released), every call bounded by a time limit. JavaScriptCore's public API cannot interrupt a
 * script, so a call that overruns its limit gives no answer and its thread is abandoned to it: the next call gets a new
 * thread and new contexts. After [MAX_ABANDONED] such threads no script runs again in the process (every lookup gives no
 * answer, so the next setting or a direct connection), which bounds what a hostile script can hold to that many threads.
 */
internal object PacRunner {
    const val MAX_CONTEXTS: Int = 8
    const val MAX_ABANDONED: Int = 2

    private class Worker(
        val dispatcher: CloseableCoroutineDispatcher,
    ) {
        /** Source key → (script, its context); touched only on [dispatcher]'s thread. */
        val contexts = LinkedHashMap<String, Pair<String, PacContext>>()

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
    }

    private val lock = Mutex()
    private var worker: Worker? = null
    private var abandoned = 0

    /** Threads given up to scripts that overran their limit (tests). */
    val abandonedThreads: Int get() = abandoned

    /**
     * `FindProxyForURL([url], [host])` of [script] (cached under [key]), or null when the script cannot be loaded, throws,
     * answers no string, or takes longer than [timeoutMillis] once it runs.
     */
    suspend fun findProxy(
        key: String,
        script: String,
        url: String,
        host: String,
        timeoutMillis: Long,
    ): String? {
        val w =
            lock.withLock {
                if (abandoned >= MAX_ABANDONED) return null
                worker ?: Worker(newSingleThreadContext("kuicksilver-pac")).also { worker = it }
            }
        val started = AtomicInt(0)
        val call =
            GlobalScope.async(w.dispatcher) {
                started.value = 1
                runCatching { w.find(key, script, url, host) }
            }
        val result = withTimeoutOrNull(timeoutMillis) { call.await() }
        if (result != null) return result.getOrNull()
        call.cancel()
        if (started.value == 1 && !call.isCompleted) {
            // the script still runs: its thread is lost to it
            lock.withLock {
                if (worker === w) {
                    worker = null
                    abandoned++
                }
            }
        }
        return null
    }

    /** Tests: forget the abandoned threads, so later tests run scripts again. */
    suspend fun resetForTest() {
        lock.withLock {
            abandoned = 0
            worker = null
        }
    }
}
