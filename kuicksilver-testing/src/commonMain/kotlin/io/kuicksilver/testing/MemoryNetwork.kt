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
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.fetchAndIncrement
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * An in-memory UDP network for application tests: no sockets, no ports, the same behaviour on every platform. Each
 * [open] binds a [DatagramIo] at an address; a datagram reaches the socket bound to its destination or vanishes, like
 * UDP. Plug it into an endpoint with `quicEndpointConfig { io = { network.open(it) } }`; a client migrates by passing
 * `network.open(newAddress)` to `migrate`. Safe to share between endpoint loops running on different threads.
 *
 * Like UDP sockets, each socket holds at most [receiveBuffer] unread datagrams and drops (and counts in [dropped]) what
 * arrives on top; a datagram larger than the receiver's slot is dropped, not truncated; `open` on port 0 binds a free
 * ephemeral port when [assignEphemeralPorts] is true.
 *
 * @param receiveBuffer Unread datagrams a socket holds before it drops new ones; at least 1.
 * @param assignEphemeralPorts Whether `open` on port 0 picks a free port (49152 and up) instead of binding port 0 itself.
 */
public class MemoryNetwork
    @ExperimentalKuicksilverApi
    constructor(
        public val receiveBuffer: Int,
        public val assignEphemeralPorts: Boolean = true,
    ) {
    /** A network whose sockets hold 256 unread datagrams and assign ephemeral ports. */
    public constructor() : this(DEFAULT_RECEIVE_BUFFER)

    init {
        require(receiveBuffer >= 1) { "receiveBuffer must be at least 1" }
    }

    private val sockets = AtomicReference<Map<InetSocketAddress, MemorySocket>>(emptyMap())
    private val cutAddresses = AtomicReference<Set<InetSocketAddress>>(emptySet())
    private val droppedCount = AtomicLong(0)
    private val nextEphemeral = AtomicLong(EPHEMERAL_FIRST.toLong())

    /** Largest datagram the network carries (bytes); bigger ones vanish, like a path that drops instead of fragmenting. */
    @Volatile public var mtu: Int = 65_535

    /** Datagrams that found no socket at their destination, crossed a [cut] address, exceeded [mtu] or the receiver's slot, or met a full receive buffer. */
    public val dropped: Long get() = droppedCount.load()

    /**
     * Binds a socket at [local]; IllegalStateException while another open socket holds the address. Closing the socket frees
     * it. Port 0 binds a free ephemeral port of the same host when [assignEphemeralPorts] is true (the socket's `localAddress`
     * says which).
     */
    public fun open(local: InetSocketAddress): DatagramIo {
        while (true) {
            val current = sockets.load()
            val address = if (local.port == 0 && assignEphemeralPorts) ephemeral(local.hostname, current) else local
            check(address !in current) { "$address is already bound on this MemoryNetwork" }
            val socket = MemorySocket(this, address, receiveBuffer)
            if (sockets.compareAndSet(current, current + (address to socket))) return socket
        }
    }

    /** The next free port of [host] in 49152..65535 (RFC 6335 dynamic ports), wrapping around. */
    private fun ephemeral(
        host: String,
        bound: Map<InetSocketAddress, MemorySocket>,
    ): InetSocketAddress {
        repeat(EPHEMERAL_COUNT) {
            val port = EPHEMERAL_FIRST + (nextEphemeral.fetchAndIncrement() - EPHEMERAL_FIRST).mod(EPHEMERAL_COUNT.toLong()).toInt()
            val candidate = InetSocketAddress(host, port)
            if (candidate !in bound) return candidate
        }
        throw IllegalStateException("no free ephemeral port on $host")
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
        if (from in cut || to in cut || bytes.size > mtu || target == null || !target.offer(bytes, from)) countDrop()
    }

    internal fun countDrop() {
        droppedCount.incrementAndFetch()
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

    private companion object {
        const val DEFAULT_RECEIVE_BUFFER = 256
        const val EPHEMERAL_FIRST = 49152
        const val EPHEMERAL_COUNT = 65536 - EPHEMERAL_FIRST
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

/** One socket of a [MemoryNetwork]: an inbox of [receiveBuffer] datagrams, portable capabilities (no ECN, no GSO/GRO, no DF). */
internal class MemorySocket(
    private val network: MemoryNetwork,
    override val localAddress: InetSocketAddress,
    receiveBuffer: Int,
) : DatagramIo {
    private val inbox = Channel<Pair<ByteArray, InetSocketAddress>>(receiveBuffer)
    override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(IoCapabilities.Portable)

    fun offer(
        bytes: ByteArray,
        from: InetSocketAddress,
    ): Boolean = inbox.trySend(bytes to from).isSuccess

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        // like a socket: a non-empty buffer answers at once, after a yield, so a receiver on a busy socket shares its dispatcher;
        // the yield comes before the take, so a receiver cancelled there loses nothing
        @OptIn(ExperimentalCoroutinesApi::class)
        if (!inbox.isEmpty) yield()
        while (true) {
            val (bytes, from) = inbox.tryReceive().getOrNull() ?: inbox.receive()
            if (bytes.size > into.segmentSize) {
                network.countDrop() // too large for the slot: dropped like a DF datagram, never truncated
                continue
            }
            val i = into.count
            into.buffer(i).copyFrom(bytes, 0, 0, bytes.size)
            into.setLength(i, bytes.size)
            into.setAddress(i, from)
            into.setEcn(i, Ecn.NotEct)
            return 1
        }
    }

    override suspend fun send(batch: PacketBatch): Int = trySend(batch)

    /** Hands every addressed slot to the network (what happens there is UDP's business) and counts those; a closed socket sends nothing. */
    override fun trySend(batch: PacketBatch): Int {
        if (closed) return 0
        var sent = 0
        for (i in 0 until batch.count) {
            network.deliver(
                localAddress,
                batch.address(i) ?: continue,
                batch.buffer(i).toByteArray(batch.length(i)),
            )
            sent++
        }
        return sent
    }

    @Volatile private var closed = false

    override fun close() {
        closed = true
        if (inbox.close()) network.unbind(this)
    }
}
