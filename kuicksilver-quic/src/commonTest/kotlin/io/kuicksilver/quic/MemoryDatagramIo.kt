// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.yield

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

    /** A datagram for which this answers true is lost (set by the test thread, read by the loops). */
    @kotlin.concurrent.Volatile
    var lose: ((from: InetSocketAddress, to: InetSocketAddress, bytes: ByteArray) -> Boolean)? = null

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

    // copied on write: the loops read it while the test thread changes it
    @kotlin.concurrent.Volatile
    private var held: Map<InetSocketAddress, Channel<Pair<InetSocketAddress, ByteArray>>> = emptyMap()

    /** From now on datagrams to [addr] wait (none lost) until [release]: a stalled return path that orders a test's steps. */
    fun hold(addr: InetSocketAddress) {
        held = held + (addr to Channel(Channel.UNLIMITED))
    }

    /** Delivers what [hold] kept for [addr], in order, and lets later datagrams through again. */
    fun release(addr: InetSocketAddress) {
        val q = held[addr] ?: return
        held = held - addr
        q.close()
        while (true) {
            val (from, bytes) = q.tryReceive().getOrNull() ?: break
            deliver(from, addr, bytes)
        }
    }

    internal fun deliver(
        from: InetSocketAddress,
        to: InetSocketAddress,
        bytes: ByteArray,
    ) {
        if (from in cut || to in cut || bytes.size > mtu || lose?.invoke(from, to, bytes) == true) {
            dropped++
            return
        }
        held[to]?.let { if (it.trySend(from to bytes).isSuccess) return } // closed by release: delivered directly
        val target = sockets[to]
        if (target == null || target.closed || target.deaf) {
            dropped++
            return
        }
        if (target.inbox.trySend(bytes to from).isSuccess) target.received++ else dropped++ // a full receive buffer
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
) : DatagramIo,
    QueuedReceive,
    DfFamilyRestricted {
    /** Fault injection: the next send skips its first slot for want of DF (reported by [takeDfRefusals]) and then throws. */
    @kotlin.concurrent.Volatile
    var refuseThenThrow: Boolean = false
    private val dfRefused = ArrayList<InetSocketAddress>()
    override val noDfFamily: IpFamily? get() = null

    override fun takeDfRefusals(): List<InetSocketAddress> = dfRefused.toList().also { dfRefused.clear() }

    /** Like a socket's receive buffer: 256 unread datagrams, then drops (as the public MemoryNetwork). */
    internal val inbox = Channel<Pair<ByteArray, InetSocketAddress>>(256)
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

    private var failure: SocketDefunctException? = null

    /** Fault injection: from now on receive and send throw [e], as a socket iOS reclaimed in the background (a waiting receive wakes with it). */
    fun failWith(e: SocketDefunctException) {
        failure = e
        inbox.close(e)
    }

    /** One-shot signals: an interrupt ([interruptReceive]), a change of [stalled]. */
    private val interrupts = Channel<Unit>(Channel.CONFLATED)
    private val stallChanged = Channel<Unit>(Channel.CONFLATED)

    /**
     * While set, a receive takes nothing from the queue (a receive whose thread has not handed its datagrams back yet: a frozen
     * process just woken, a stopped debugger): datagrams wait in the queue, which only [receiveQueued] empties. A receive in
     * flight returns 0 when interrupted.
     */
    @kotlin.concurrent.Volatile
    var stalled: Boolean = false
        set(value) {
            field = value
            stallChanged.trySend(Unit)
        }

    /** While set, an interrupted receive returns only once this completes (a blocking receive that ends with its wait slice). */
    @kotlin.concurrent.Volatile
    var interruptGate: CompletableDeferred<Unit>? = null

    /** More datagrams [receiveQueued] finds once the queue is empty, from ([from], bytes); null ends them (a flood without end). */
    @kotlin.concurrent.Volatile
    var queuedSource: (() -> Pair<InetSocketAddress, ByteArray>?)? = null

    /** Calls of [interruptReceive] and datagrams [receiveQueued] took (test counters). */
    @kotlin.concurrent.Volatile
    var interruptsSeen: Long = 0
        private set

    @kotlin.concurrent.Volatile
    var queuedTaken: Long = 0
        private set

    private fun put(
        into: PacketBatch,
        bytes: ByteArray,
        from: InetSocketAddress,
    ): Int {
        val i = into.count
        into.buffer(i).copyFrom(bytes, 0, 0, bytes.size)
        into.setLength(i, bytes.size)
        into.setAddress(i, from)
        return 1
    }

    override suspend fun receive(into: PacketBatch): Int {
        failure?.let { throw it }
        if (into.count >= into.capacity) return 0
        interrupts.tryReceive() // left by a receive that returned before it saw it
        while (true) {
            if (!stalled) {
                // like a socket: a non-empty buffer answers at once, after a yield (taken before the datagram, so a cancelled receiver loses nothing)
                @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
                if (!inbox.isEmpty) yield()
                inbox.tryReceive().getOrNull()?.let { (bytes, from) -> return put(into, bytes, from) }
            }
            val got: Pair<ByteArray, InetSocketAddress>? =
                select {
                    if (!stalled) inbox.onReceive { it }
                    interrupts.onReceive { INTERRUPTED }
                    stallChanged.onReceive { null }
                }
            if (got === INTERRUPTED) {
                interruptGate?.await()
                return 0
            }
            if (got != null) return put(into, got.first, got.second)
        }
    }

    override fun receiveQueued(into: PacketBatch): Int {
        if (failure != null || closed) return 0
        var n = 0
        while (into.count < into.capacity) {
            val (bytes, from) =
                inbox.tryReceive().getOrNull()?.let { it.first to it.second }
                    ?: queuedSource?.invoke()?.let { it.second to it.first }
                    ?: break
            put(into, bytes, from)
            n++
        }
        queuedTaken += n
        return n
    }

    override fun interruptReceive() {
        interruptsSeen++
        interrupts.trySend(Unit)
    }

    /** Runs before each suspending send: a test stalls the loop's flush in it, as a socket without room would. */
    var beforeSend: (suspend () -> Unit)? = null

    override suspend fun send(batch: PacketBatch): Int {
        beforeSend?.invoke()
        return trySend(batch)
    }

    /** Fault injection on sends only (receive goes on): the next [sendFailuresLeft] sends throw it, then it clears. */
    @kotlin.concurrent.Volatile
    var sendFailure: Throwable? = null

    @kotlin.concurrent.Volatile
    var sendFailuresLeft: Int = Int.MAX_VALUE

    override fun trySend(batch: PacketBatch): Int {
        failure?.let { throw it }
        if (refuseThenThrow && batch.count > 0) {
            refuseThenThrow = false
            batch.address(0)?.let { dfRefused += it }
            throw kotlinx.io.IOException("test: the send failed after a skipped slot")
        }
        sendFailure?.let {
            if (--sendFailuresLeft <= 0) sendFailure = null
            throw it
        }
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
        private val INTERRUPTED = ByteArray(0) to InetSocketAddress("0.0.0.0", 0)

        /** Two sockets on a fresh network, 10.0.0.1:1111 and 10.0.0.2:2222. */
        fun pair(): Pair<MemoryDatagramIo, MemoryDatagramIo> {
            val net = MemoryNetwork()
            return net.open(InetSocketAddress("10.0.0.1", 1111)) to
                net.open(InetSocketAddress("10.0.0.2", 2222))
        }
    }
}
