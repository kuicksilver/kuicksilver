// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import kotlinx.coroutines.sync.Mutex
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * At most one WebSocket connection in the CONNECTING state per remote host (RFC 6455 section 4.1, step 2: "There MUST be
 * no more than one connection in a CONNECTING state. If multiple connections to the same IP address are attempted
 * simultaneously, the client MUST serialize them", and a client with a connection to the remote host "MUST wait until
 * that connection has been established or for that connection to have failed", "even if the remote host is known by
 * another name"). The remote host is the IP address, whatever the port: a key is the address alone, for each address
 * the name resolves to when the engine resolves it (a WebSocket holds every address it may connect to, so two names that
 * share one wait for each other), else the name alone when a proxy resolves it ("the client MUST assume for the purposes
 * of this step that each host name refers to a distinct remote host"). Keys are taken in sorted order, so two
 * WebSockets never wait for each other's keys; an entry lives only while a WebSocket holds or waits for it.
 */
@OptIn(ExperimentalAtomicApi::class)
internal class WebSocketConnecting {
    /** One remote host: its lock, and the WebSockets holding or waiting for it. */
    class Entry {
        val mutex = Mutex()
        var users = 0
    }

    private val lock = SpinLock()
    private val entries = HashMap<String, Entry>()

    /** The keys one WebSocket holds from [acquire]; [release] gives them back, once, however often it is called. */
    inner class Held internal constructor(
        private val keys: List<String>,
        private val taken: List<Entry>,
    ) {
        private val released = AtomicInt(0)

        fun release() {
            if (!released.compareAndSet(0, 1)) return
            for (e in taken.asReversed()) e.mutex.unlock()
            forget(keys, taken)
        }
    }

    /**
     * Waits until no other WebSocket holds any of [keys], then holds them all. Cancellation while waiting leaves none
     * held.
     */
    suspend fun acquire(keys: Collection<String>): Held {
        val sorted = keys.distinct().sorted()
        val taken = lock.withLock { sorted.map { k -> entries.getOrPut(k) { Entry() }.also { it.users++ } } }
        val held = ArrayList<Mutex>(taken.size)
        try {
            for (e in taken) {
                e.mutex.lock()
                held += e.mutex
            }
        } catch (e: Throwable) {
            for (m in held.asReversed()) m.unlock()
            forget(sorted, taken)
            throw e
        }
        return Held(sorted, taken)
    }

    private fun forget(
        keys: List<String>,
        taken: List<Entry>,
    ) = lock.withLock {
        keys.forEachIndexed { i, k -> if (--taken[i].users == 0) entries.remove(k) }
    }

    /** Remote hosts with a WebSocket connecting or waiting; for tests. */
    internal fun size(): Int = lock.withLock { entries.size }
}
