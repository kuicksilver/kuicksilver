// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * At most one WebSocket connection in the CONNECTING state per remote host (RFC 6455 section 4.1, step 2: "There MUST be
 * no more than one connection in a CONNECTING state", and a client with a connection to a host and port pair "MUST
 * wait until that connection has been established or for that connection to have failed", whatever name led to it).
 * A remote host is a key: `ip:port` for each address the name resolves to when the engine resolves it (a WebSocket
 * holds every address it may connect to, so two names that share one wait for each other), else the name and port when
 * a proxy resolves it (the step then has each name count as a distinct host). Keys are taken in sorted order, so two
 * WebSockets never wait for each other's keys; an entry lives only while a WebSocket holds or waits for it.
 */
internal class WebSocketConnecting {
    private class Entry {
        val mutex = Mutex()
        var users = 0
    }

    private val lock = Mutex()
    private val entries = HashMap<String, Entry>()

    /** Runs [block] (opening the connection up to the server's handshake response) while holding [keys]. */
    suspend fun <T> serialized(
        keys: Collection<String>,
        block: suspend () -> T,
    ): T {
        val sorted = keys.distinct().sorted()
        val taken = lock.withLock { sorted.map { k -> entries.getOrPut(k) { Entry() }.also { it.users++ } } }
        val held = ArrayList<Mutex>(taken.size)
        try {
            for (e in taken) {
                e.mutex.lock()
                held += e.mutex
            }
            return block()
        } finally {
            for (m in held.asReversed()) m.unlock()
            withContext(NonCancellable) {
                lock.withLock {
                    sorted.forEachIndexed { i, k -> if (--taken[i].users == 0) entries.remove(k) }
                }
            }
        }
    }

    /** Remote hosts with a WebSocket connecting or waiting; for tests. */
    internal suspend fun size(): Int = lock.withLock { entries.size }
}
