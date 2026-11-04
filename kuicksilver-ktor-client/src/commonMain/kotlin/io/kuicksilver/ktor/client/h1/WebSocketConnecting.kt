// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client.h1

import io.kuicksilver.ktor.client.socketHost
import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
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
    private val waits = MutableStateFlow(0)

    /** How many [acquire] calls so far found a key in use by another WebSocket and waited (tests, no polling). */
    val waitsForTest: StateFlow<Int> get() = waits

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
        var contended = false
        val taken =
            lock.withLock {
                sorted.map { k ->
                    entries.getOrPut(k) { Entry() }.also {
                        it.users++
                        if (it.users > 1) contended = true
                    }
                }
            }
        if (contended) waits.update { it + 1 }
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

    /**
     * [acquire] without waiting: the keys when no other WebSocket holds any of them, else null and nothing held. For a
     * connection that is open already (the h3/h1 race opened it), which must not wait for the keys while it holds its pool
     * slot.
     */
    fun tryAcquire(keys: Collection<String>): Held? {
        val sorted = keys.distinct().sorted()
        val taken = lock.withLock { sorted.map { k -> entries.getOrPut(k) { Entry() }.also { it.users++ } } }
        val held = ArrayList<Mutex>(taken.size)
        for (e in taken) {
            if (!e.mutex.tryLock()) {
                for (m in held.asReversed()) m.unlock()
                forget(sorted, taken)
                return null
            }
            held += e.mutex
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

    companion object {
        /**
         * The key of the remote host at [address]. An IPv4-mapped IPv6 address (`::ffff:0:0/96`, RFC 4291 section
         * 2.5.5.2) is that IPv4 host: Kotlin/Native's `getaddrinfo` keeps the AF_INET6 form of `[::ffff:127.0.0.1]`
         * where the JVM gives an `Inet4Address`, and a resolver may return mapped AAAA records.
         */
        fun addressKey(address: TcpAddress): String {
            val b = address.bytes
            val mapped = b.size == 16 && (0 until 10).all { b[it] == 0.toByte() } && b[10] == FF && b[11] == FF
            if (!mapped) return "address ${address.hostText}"
            return "address ${b[12].toUByte()}.${b[13].toUByte()}.${b[14].toUByte()}.${b[15].toUByte()}"
        }

        /**
         * The key of the remote host named [host] when a proxy resolves it: DNS names compare without case (RFC 4343),
         * and a final dot (an absolute name) names the same host; an IPv6 literal loses its brackets.
         */
        fun nameKey(host: String): String = "name ${socketHost(host).lowercase().removeSuffix(".")}"

        private const val FF: Byte = -1
    }
}
