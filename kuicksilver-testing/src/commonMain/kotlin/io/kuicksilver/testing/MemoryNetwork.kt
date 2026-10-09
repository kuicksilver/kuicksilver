// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.testing

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PacketBatch
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * An in-memory UDP network for application tests: no sockets, no ports, the same behaviour on every platform. Each
 * [open] binds a [DatagramIo] at an address; a datagram reaches the socket bound to its destination or vanishes, like
 * UDP. Plug it into an endpoint with `quicEndpointConfig { io = { network.open(it) } }`; a client migrates by passing
 * `network.open(newAddress)` to `migrate`. Safe to share between endpoint loops running on different threads.
 */
public class MemoryNetwork {
    private val sockets = AtomicReference<Map<InetSocketAddress, MemorySocket>>(emptyMap())
    private val cutAddresses = AtomicReference<Set<InetSocketAddress>>(emptySet())
    private val droppedCount = AtomicLong(0)

    /** Largest datagram the network carries (bytes); bigger ones vanish, like a path that drops instead of fragmenting. */
    @Volatile public var mtu: Int = 65_535

    /** Datagrams that found no socket at their destination, crossed a [cut] address or exceeded [mtu]. */
    public val dropped: Long get() = droppedCount.load()

    /** Binds a socket at [local]; IllegalStateException while another open socket holds the address. Closing the socket frees it. */
    public fun open(local: InetSocketAddress): DatagramIo {
        val socket = MemorySocket(this, local)
        while (true) {
            val current = sockets.load()
            check(local !in current) { "$local is already bound on this MemoryNetwork" }
            if (sockets.compareAndSet(current, current + (local to socket))) return socket
        }
    }

    /** From now on nothing reaches [address] and nothing it sends arrives: the address went dark (a dead Wi-Fi). */
    public fun cut(address: InetSocketAddress) {
        update(cutAddresses) { it + address }
    }

    /** Undoes [cut]. */
    public fun restore(address: InetSocketAddress) {
        update(cutAddresses) { it - address }
    }

    internal fun deliver(
        from: InetSocketAddress,
        to: InetSocketAddress,
        bytes: ByteArray,
    ) {
        val cut = cutAddresses.load()
        val target = sockets.load()[to]
        if (from in cut || to in cut || bytes.size > mtu || target == null || !target.offer(bytes, from)) droppedCount.incrementAndFetch()
    }

    internal fun unbind(socket: MemorySocket) {
        update(sockets) {
            if (it[socket.localAddress] ===
                socket
            ) {
                it - socket.localAddress
            } else {
                it
            }
        }
    }

    private inline fun <T> update(
        ref: AtomicReference<T>,
        f: (T) -> T,
    ) {
        while (true) {
            val v = ref.load()
            if (ref.compareAndSet(v, f(v))) return
        }
    }
}

/** One socket of a [MemoryNetwork]: unbounded inbox, portable capabilities (no ECN, no GSO/GRO, no DF). */
internal class MemorySocket(
    private val network: MemoryNetwork,
    override val localAddress: InetSocketAddress,
) : DatagramIo {
    private val inbox = Channel<Pair<ByteArray, InetSocketAddress>>(Channel.UNLIMITED)
    override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(IoCapabilities.Portable)

    fun offer(
        bytes: ByteArray,
        from: InetSocketAddress,
    ): Boolean = inbox.trySend(bytes to from).isSuccess

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        val (bytes, from) = inbox.receive()
        val i = into.count
        val n = minOf(bytes.size, into.segmentSize)
        into.buffer(i).copyFrom(bytes, 0, 0, n)
        into.setLength(i, n)
        into.setAddress(i, from)
        into.setEcn(i, Ecn.NotEct)
        return 1
    }

    override suspend fun send(batch: PacketBatch): Int = trySend(batch)

    override fun trySend(batch: PacketBatch): Int {
        for (i in 0 until batch.count) {
            network.deliver(
                localAddress,
                batch.address(i) ?: continue,
                batch.buffer(i).toByteArray(batch.length(i)),
            )
        }
        return batch.count
    }

    override fun close() {
        if (inbox.close()) network.unbind(this)
    }
}
