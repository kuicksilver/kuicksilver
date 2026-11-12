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
 * another name").
 *
 * The invariant: while a WebSocket is CONNECTING it holds the key of its URL's host name ([nameKey]) and the key of the IP
 * address its connection actually goes to ([addressKey], whatever the port), so two WebSockets to one name, or to one
 * address under any names, never are CONNECTING together. Over HTTP/1.1 a WebSocket first takes the name and the
 * addresses its resolution answered with (the families that answered, [io.kuicksilver.ktor.client.RequestDns.answered]),
 * then, once it has its connection, the connection's own address ([Held.tryAdd]: when another WebSocket holds that one, it
 * gives the connection back and waits for every key); over HTTP/3 it takes the name and the address of the QUIC
 * connection it uses. Through a proxy that resolves the name, the name alone ("the client MUST assume for the purposes of
 * this step that each host name refers to a distinct remote host"). Keys are taken in sorted order and an added key is
 * never waited for, so two WebSockets never wait for each other's keys; an entry lives only while a WebSocket holds or
 * waits for it.
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

    private val acquired = MutableStateFlow(0)

    /** How many [acquire] calls so far got their keys (tests, no polling). */
    val acquiredForTest: StateFlow<Int> get() = acquired

    /** The keys held or waited for now (tests). */
    internal fun keysForTest(): Set<String> = lock.withLock { entries.keys.toSet() }

    /** The keys one WebSocket holds from [acquire]; [release] gives them back, once, however often it is called. */
    inner class Held internal constructor(
        keys: List<String>,
        taken: List<Entry>,
    ) {
        private val keys = keys.toMutableList()
        private val taken = taken.toMutableList()
        private val released = AtomicInt(0)

        /** The keys held. */
        val held: List<String> get() = keys.toList()

        /**
         * Holds [key] too when no other WebSocket holds it, without waiting (a key added while others are held is never
         * waited for, so no two WebSockets wait for each other); false, and nothing more held, when another one does.
         */
        fun tryAdd(key: String): Boolean {
            if (key in keys) return true
            val e = lock.withLock { entries.getOrPut(key) { Entry() }.also { it.users++ } }
            if (!e.mutex.tryLock()) {
                forget(listOf(key), listOf(e))
                return false
            }
            keys += key
            taken += e
            return true
        }

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
        acquired.update { it + 1 }
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
         * where the JVM gives an `Inet4Address`, and a resolver may return mapped AAAA records. A link-local address's
         * zone is left out: a connected socket's peer address may come without one, and one key for an address on every
         * interface only serializes more than needed.
         */
        fun addressKey(address: TcpAddress): String {
            val b = address.bytes
            val mapped = b.size == 16 && (0 until 10).all { b[it] == 0.toByte() } && b[10] == FF && b[11] == FF
            if (!mapped) return "address ${address.hostText.substringBefore('%')}"
            return "address ${b[12].toUByte()}.${b[13].toUByte()}.${b[14].toUByte()}.${b[15].toUByte()}"
        }

        /**
         * The key of the remote host named [host] (every WebSocket holds its URL's; through a proxy that resolves names, the
         * only one): DNS names compare without case (RFC 4343), and a final dot (an absolute name) names the same host; an
         * IPv6 literal loses its brackets.
         */
        fun nameKey(host: String): String = "name ${socketHost(host).lowercase().removeSuffix(".")}"

        /** The key of the remote host at [ip] (a socket's or QUIC path's peer, 4 or 16 bytes), or null for anything else. */
        fun ipKey(ip: ByteArray): String? = if (ip.size == 4 || ip.size == 16) addressKey(TcpAddress(ip, 0)) else null

        /**
         * The IP address of a connected socket's peer [address]: its bytes as Ktor resolved them, else (where a platform's
         * Ktor gives none) the address literal the socket was created with, parsed here and never looked up; null for a
         * peer that is no IP address.
         */
        fun peerIp(address: io.ktor.network.sockets.SocketAddress?): ByteArray? {
            val inet = address as? io.ktor.network.sockets.InetSocketAddress ?: return null
            val bytes =
                try {
                    inet.resolveAddress()
                } catch (e: Exception) {
                    null
                }
            return bytes?.takeIf { it.size == 4 || it.size == 16 } ?: parseIpLiteral(inet.hostname)
        }

        /**
         * The 4 or 16 bytes of the IP address literal [text] (dotted IPv4; IPv6 in any RFC 4291 section 2.2 form, brackets
         * and a `%zone` allowed), or null when it is no literal.
         */
        internal fun parseIpLiteral(text: String): ByteArray? {
            val t = text.removePrefix("[").removeSuffix("]").substringBefore('%')
            io.kuicksilver.ktor.network
                .parseIpv4Literal(t)
                ?.let { return it }
            if (':' !in t) return null
            var s = t
            var tail4: ByteArray? = null
            val last = s.lastIndexOf(':')
            if ('.' in s.substring(last + 1)) {
                tail4 = io.kuicksilver.ktor.network
                    .parseIpv4Literal(s.substring(last + 1)) ?: return null
                s = s.substring(0, last + 1) + "0:0"
            }
            val halves = s.split("::")
            if (halves.size > 2) return null

            fun groups(x: String) = if (x.isEmpty()) emptyList() else x.split(':')
            val head = groups(halves[0])
            val tail = if (halves.size == 2) groups(halves[1]) else emptyList()
            val n = head.size + tail.size
            if ((halves.size == 1 && n != 8) || (halves.size == 2 && n > 7)) return null
            val out = ByteArray(16)
            for ((i, g) in (head + List(8 - n) { "0" } + tail).withIndex()) {
                if (g.isEmpty() || g.length > 4 || !g.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
                val v = g.toIntOrNull(16) ?: return null
                out[2 * i] = (v shr 8).toByte()
                out[2 * i + 1] = v.toByte()
            }
            tail4?.copyInto(out, 12)
            return out
        }

        private const val FF: Byte = -1
    }
}
