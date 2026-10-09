// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** An in-memory UDP "network" (all platforms, no sockets): datagrams are routed to the [MemoryDatagramIo] bound to their destination address, or dropped. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class MemoryNetwork {
    private val sockets = HashMap<InetSocketAddress, MemoryDatagramIo>()
    private val cut = HashSet<InetSocketAddress>()

    /** Datagrams whose destination had no socket (or was cut). */
    var dropped: Long = 0
        private set

    /** Largest datagram the network carries; bigger ones vanish (DF, no ICMP). */
    var mtu: Int = 65_535

    /** Binds a socket at [local]; a [deaf] one never delivers what it receives (a dead path). */
    fun open(
        local: InetSocketAddress,
        deaf: Boolean = false,
        df: Boolean = false,
    ): MemoryDatagramIo {
        val io = MemoryDatagramIo(this, local, deaf, df)
        sockets[local] =
            io
        return io
    }

    /** From now on nothing reaches [addr] and nothing it sends arrives (the address went dark). */
    fun cut(addr: InetSocketAddress) {
        cut += addr
    }

    fun uncut(addr: InetSocketAddress) {
        cut -= addr
    }

    internal fun deliver(
        from: InetSocketAddress,
        to: InetSocketAddress,
        bytes: ByteArray,
    ) {
        if (from in cut || to in cut || bytes.size > mtu) {
            dropped++
            return
        }
        val target = sockets[to]
        if (target == null || target.closed || target.deaf) {
            dropped++
            return
        }
        target.inbox.trySend(bytes to from)
        target.received++
    }

    internal fun unbind(io: MemoryDatagramIo) {
        if (sockets[io.localAddress] === io) sockets.remove(io.localAddress)
    }
}

/** One socket of a [MemoryNetwork]. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class MemoryDatagramIo internal constructor(
    private val net: MemoryNetwork,
    override val localAddress: InetSocketAddress,
    internal val deaf: Boolean,
    df: Boolean = false,
) : DatagramIo {
    internal val inbox = Channel<Pair<ByteArray, InetSocketAddress>>(Channel.UNLIMITED)
    override val capabilities: StateFlow<IoCapabilities> =
        MutableStateFlow(
            if (df) {
                IoCapabilities(
                    ecnSend = false,
                    ecnReceive = false,
                    gsoMaxSegments = 1,
                    gro = false,
                    df = true,
                    batch = 1,
                )
            } else {
                IoCapabilities.Portable
            },
        )

    /** Datagrams sent and delivered through this socket (test counters). */
    var sent: Long = 0
        private set
    var received: Long = 0
        internal set
    var closed: Boolean = false
        private set

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        val (bytes, from) = inbox.receive()
        val i = into.count
        into.buffer(i).copyFrom(bytes, 0, 0, bytes.size)
        into.setLength(i, bytes.size)
        into.setAddress(i, from)
        return 1
    }

    override suspend fun send(batch: PacketBatch): Int = trySend(batch)

    override fun trySend(batch: PacketBatch): Int {
        for (i in 0 until batch.count) {
            net.deliver(localAddress, batch.address(i) ?: continue, batch.buffer(i).toByteArray(batch.length(i)))
            sent++
        }
        return batch.count
    }

    override fun close() {
        if (!closed) {
            closed = true
            inbox.close()
            net.unbind(this)
        }
    }

    companion object {
        /** Two sockets on a fresh network, 10.0.0.1:1111 and 10.0.0.2:2222. */
        fun pair(): Pair<MemoryDatagramIo, MemoryDatagramIo> {
            val net = MemoryNetwork()
            return net.open(InetSocketAddress("10.0.0.1", 1111)) to
                net.open(InetSocketAddress("10.0.0.2", 2222))
        }
    }
}
