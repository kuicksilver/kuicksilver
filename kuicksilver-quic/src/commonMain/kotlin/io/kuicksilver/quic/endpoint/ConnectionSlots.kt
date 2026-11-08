// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.quic.endpoint

import io.kuicksilver.quic.core.AddressClass
import kotlin.concurrent.atomics.AtomicArray
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.random.Random

/**
 * The slots of `QuicEndpointConfig.maxConnections` and `maxConnectionsPerIp`. Every connection an endpoint holds takes one
 * from its creation until it is removed; a server connection also takes one of its client's IP address, reserved when its
 * Initial passes the hard limits and given back when no connection comes of it. The loops of a group share one [Shared], so
 * both limits bound the endpoint as a whole, whatever loop a connection lives on (SO_REUSEPORT spreads one address's ports
 * over the loops, the in-process dispatch hashes connection IDs). A lone endpoint keeps a [Local] one, as before.
 * At most one entry per address that holds a connection: the table never grows past the connections themselves.
 */
internal sealed class ConnectionSlots {
    /** Connections holding a slot. */
    abstract val total: Int

    /**
     * Takes a server connection's slot and one of [ip], or nothing: -1 when [maxTotal] slots or [maxPerIp] of [ip] are taken
     * (null: no per-address limit), else the connections of [ip] before this one.
     */
    abstract fun acquire(
        ip: AddressClass.IpKey,
        maxTotal: Int,
        maxPerIp: Int?,
    ): Int

    /** Takes a slot past the limits: a client connection, which the application asked for. */
    abstract fun acquireUnchecked()

    /** Gives back a slot taken by [acquire] (with its [ip]) or [acquireUnchecked] (null). */
    abstract fun release(ip: AddressClass.IpKey?)

    /** Addresses holding connections, for `QuicResourceProbe` (a group's loops report it once, on loop 0). */
    abstract fun addressesForProbe(loopIndex: Int): Int

    /** One endpoint's slots, used on its loop's thread only. */
    class Local : ConnectionSlots() {
        private val perIp = HashMap<AddressClass.IpKey, Int>()
        override var total: Int = 0
            private set

        override fun acquire(
            ip: AddressClass.IpKey,
            maxTotal: Int,
            maxPerIp: Int?,
        ): Int {
            if (total >= maxTotal) return -1
            val n = perIp[ip] ?: 0
            if (maxPerIp != null && n >= maxPerIp) return -1
            perIp[ip] = n + 1
            total++
            return n
        }

        override fun acquireUnchecked() {
            total++
        }

        override fun release(ip: AddressClass.IpKey?) {
            total--
            if (ip == null) return
            val n = (perIp[ip] ?: 1) - 1
            if (n <= 0) perIp.remove(ip) else perIp[ip] = n
        }

        override fun addressesForProbe(loopIndex: Int): Int = perIp.size
    }

    /**
     * A loop group's slots, taken and given back from every loop's thread. The total is one atomic counter raised by
     * compare-and-set below the limit. The addresses are kept as [ResetTokenIndex] keeps its tokens: [BUCKETS] buckets chosen
     * by SipHash under a random key (a client cannot aim its addresses at one bucket), each a short immutable array replaced
     * with a compare-and-set, so a loop preempted in the middle of a change never stalls another. Only admissions and removals
     * come here, never a packet of an established connection.
     */
    class Shared(
        random: Random,
    ) : ConnectionSlots() {
        private val k0 = random.nextLong()
        private val k1 = random.nextLong()
        private val count = AtomicInt(0)
        private val addresses = AtomicInt(0)

        private class Entry(
            val hash: Long,
            val ip: AddressClass.IpKey,
            val n: Int,
        )

        private val buckets = AtomicArray(Array(BUCKETS) { EMPTY })

        override val total: Int get() = count.load()

        override fun acquire(
            ip: AddressClass.IpKey,
            maxTotal: Int,
            maxPerIp: Int?,
        ): Int {
            while (true) {
                val t = count.load()
                if (t >= maxTotal) return -1
                if (count.compareAndSet(t, t + 1)) break
            }
            val before = change(ip) { n -> if (maxPerIp != null && n >= maxPerIp) n else n + 1 }
            if (maxPerIp != null && before >= maxPerIp) {
                count.decrementAndFetch() // the address is full: no slot after all
                return -1
            }
            return before
        }

        override fun acquireUnchecked() {
            count.incrementAndFetch()
        }

        override fun release(ip: AddressClass.IpKey?) {
            if (ip != null) change(ip) { n -> if (n > 0) n - 1 else 0 }
            count.decrementAndFetch()
        }

        override fun addressesForProbe(loopIndex: Int): Int = if (loopIndex == 0) addresses.load() else 0

        /** Replaces the count of [ip] by [update] of it (0: the entry goes) with one compare-and-set of its bucket; the count before. */
        private inline fun change(
            ip: AddressClass.IpKey,
            update: (Int) -> Int,
        ): Int {
            val h = SipHash.hash24(k0, k1, ip.bytes)
            val at = (h and (BUCKETS - 1).toLong()).toInt()
            while (true) {
                val b = buckets.loadAt(at)
                var k = -1
                for (i in b.indices) {
                    if (b[i].hash == h && b[i].ip == ip) {
                        k = i
                        break
                    }
                }
                val old = if (k >= 0) b[k].n else 0
                val n = update(old)
                if (n == old) return old
                val next: Array<Entry> =
                    when {
                        n == 0 -> Array(b.size - 1) { b[if (it < k) it else it + 1] }
                        k < 0 -> Array(b.size + 1) { if (it < b.size) b[it] else Entry(h, ip, n) }
                        else -> b.copyOf().also { it[k] = Entry(h, ip, n) }
                    }
                if (buckets.compareAndSetAt(at, b, next)) {
                    if (old == 0) {
                        addresses.incrementAndFetch()
                    } else if (n == 0) {
                        addresses.decrementAndFetch()
                    }
                    return old
                }
            }
        }

        private companion object {
            const val BUCKETS = 1024
            val EMPTY = emptyArray<Entry>()
        }
    }
}
