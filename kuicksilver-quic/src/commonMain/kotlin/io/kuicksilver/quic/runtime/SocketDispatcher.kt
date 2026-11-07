// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DirectReceive
import io.kuicksilver.quic.Ecn
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.NonSuspendingSend
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PacketTooBigSource
import io.kuicksilver.quic.endpoint.CidRoute
import io.kuicksilver.quic.endpoint.DispatchRoute
import io.kuicksilver.quic.endpoint.ResetTokenIndex
import io.kuicksilver.quic.endpoint.SipKey
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * `loops > 1` on one socket, where the kernel does not balance a port over several sockets (Darwin hands every datagram to the
 * last socket bound, Windows binds exclusively, a caller-supplied [DatagramIo]): one receiver hands each datagram to the loop
 * its connection ID names ([DispatchRoute]) and every loop sends through its own sender (`ksl_udp_sender`, or the shared
 * socket under a lock). Each loop sees the socket as its [LoopInbox], so [EndpointLoop] runs unchanged.
 *
 * The receiver runs on its own thread (`Dispatchers.IO`, one at a time) and blocks in the socket's receive in 100 ms slices. It
 * copies each datagram into its loop's ring ([RING] slots of one datagram each, written by the receiver and read by the loop
 * with no lock and no allocation per datagram) and wakes the loop once per receive round. When a loop's ring is full the
 * datagram is dropped and counted ([dropped], `EndpointStats.datagramsDispatchDropped`): the receiver never waits for a loop,
 * so a flood aimed at one loop costs that loop's datagrams only (threat-model 3.4). A datagram ending with a peer's reset token
 * goes to the loop whose connection holds it ([resets], RFC 9000 section 10.3.1). After each round the receiver takes the ICMP
 * Packet Too Big messages the socket queued (Linux and Android with DF) and offers each to every loop: each checks the quote
 * against its own connections (RFC 8899 section 4.6), as a loop with its own socket does.
 *
 * The socket closes with the last loop's inbox (each loop's close sends its CONNECTION_CLOSEs first). A receive failure of
 * the open socket fails every inbox with it ([LoopInbox.fail]): the loops then react as to their own socket's failure, so a
 * failed main socket ends the group and a failed preferred-address socket takes the preferred address down group-wide.
 */
internal class SocketDispatcher(
    internal val io: DatagramIo,
    senders: List<DatagramIo>,
    private val cidLength: Int,
    private val key: SipKey,
    private val resets: ResetTokenIndex? = null,
    private val allocate: (Int) -> PacketBuffer = PacketBuffer::allocate,
) {
    val loops: Int = senders.size

    /** Loop `i`'s view of the socket. */
    val inboxes: List<LoopInbox> =
        senders.mapIndexed { i, s -> if (s is NonSuspendingSend) AcceleratedLoopInbox(this, i, s) else LoopInbox(this, i, s) }

    private val droppedCount = AtomicLong(0)

    /** Datagrams dropped because their loop's ring was full. */
    val dropped: Long get() = droppedCount.load()

    private val ptbDroppedCount = AtomicLong(0)

    /** Packet Too Big messages a loop had no room for (its queue holds [KslDatagramIo.PTB_PER_DRAIN]): counted as ignored. */
    val ptbDropped: Long get() = ptbDroppedCount.load()

    internal fun ptbDroppedOne() {
        ptbDroppedCount.incrementAndFetch()
    }

    private val closed = AtomicInt(0)
    private val openInboxes = AtomicInt(loops)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO.limitedParallelism(1))

    /** The receiver (tests: it ends once the socket closed). */
    @Volatile internal var receiverForTest: Job? = null
        private set

    /** Starts the receiver; [route] tells the owner of a connection ID. */
    fun start(route: CidRoute) {
        receiverForTest = scope.launch { receive(route) }
    }

    private suspend fun receive(route: CidRoute) {
        val batch = PacketBatch(SLOTS, EndpointLoop.SLOT_SIZE, allocate)
        val direct = io as? DirectReceive
        val icmp = io as? PacketTooBigSource
        try {
            while (closed.load() == 0) {
                batch.clear()
                // the accelerated socket blocks this thread in the native receive (a shutdown wakes it); another io suspends
                if (direct != null) direct.receiveNow(batch, SLICE_MS) else io.receive(batch)
                for (i in 0 until batch.count) {
                    val len = batch.length(i)
                    val buf = batch.buffer(i)
                    val loop = DispatchRoute.loopOf(buf, len, cidLength, loops, route, key, resets)
                    if (!inboxes[loop].put(buf, len, batch.address(i)!!, batch.localAddress(i), batch.ecn(i))) {
                        droppedCount.incrementAndFetch()
                    }
                }
                icmp?.drainPacketTooBig { quote, len, dst, mtu -> for (b in inboxes) b.offerPacketTooBig(quote, len, dst, mtu) }
                for (b in inboxes) b.wake()
                currentCoroutineContext().ensureActive()
            }
        } catch (e: Throwable) {
            // a socket closed under the receive throws too: that is the close, not a failure
            if (closed.load() == 0) for (b in inboxes) b.fail(e)
        } finally {
            batch.close()
        }
    }

    /** One inbox closed; the last one closes the socket (waking the receiver). */
    internal fun inboxClosed() {
        if (openInboxes.decrementAndFetch() == 0) closeSocket()
    }

    private fun closeSocket() {
        if (!closed.compareAndSet(0, 1)) return
        try {
            io.close()
        } finally {
            scope.cancel()
        }
    }

    companion object {
        /** Datagrams a loop may have waiting: one that falls this far behind loses datagrams instead of holding up the receiver. */
        const val RING: Int = 512

        /** Datagrams per receive of the shared socket. */
        const val SLOTS: Int = 64

        /** How long one native receive blocks before the receiver checks for a close. */
        const val SLICE_MS: Int = 100
    }
}

/**
 * Loop `index`'s view of a [SocketDispatcher]'s socket: datagrams the dispatcher routed to this loop, sends through this loop's
 * own sender. The datagrams wait in a ring of [SocketDispatcher.RING] slots that the dispatcher's thread alone writes ([put]:
 * the slot, then [tail]) and the loop's thread alone reads (the slots up to [tail], then [head]). [receiveNow] takes what is
 * there, never waiting; [receive] suspends until the dispatcher's next [wake].
 */
internal open class LoopInbox(
    private val dispatcher: SocketDispatcher,
    val index: Int,
    protected val sender: DatagramIo,
) : DatagramIo,
    DirectReceive,
    PacketTooBigSource {
    private val size = SocketDispatcher.RING
    private val data: Array<ByteArray> = Array(size) { ByteArray(EndpointLoop.SLOT_SIZE) }
    private val lengths = IntArray(size)
    private val from = arrayOfNulls<InetSocketAddress>(size)
    private val locals = arrayOfNulls<InetSocketAddress>(size)
    private val ecns = Array(size) { Ecn.NotEct }

    /** Datagrams written (the dispatcher's) and read (the loop's) so far; `tail - head` wait. */
    private val tail = AtomicInt(0)
    private val head = AtomicInt(0)

    /** Datagrams arrived since the loop last looked: one signal per receive round, conflated. */
    private val signal = Channel<Unit>(Channel.CONFLATED)
    private var putSinceWake = false
    private val closed = AtomicInt(0)

    /** The shared socket's receive failed: the loop's next receive throws it. */
    @Volatile private var failure: Throwable? = null

    /** One ICMP Packet Too Big of the shared socket, copied for this loop. */
    private class Ptb(
        val quote: ByteArray,
        val dst: InetSocketAddress,
        val mtu: Int,
    )

    /** Packet Too Big messages the dispatcher offered and this loop has not taken: as many as the socket's own ring holds, newer ones dropped. */
    private val ptbs = Channel<Ptb>(KslDatagramIo.PTB_PER_DRAIN)

    /** Test hook: while set, the loop takes nothing from this inbox (a loop that falls behind). */
    @Volatile internal var holdForTest: CompletableDeferred<Unit>? = null

    override val localAddress: InetSocketAddress get() = dispatcher.io.localAddress
    override val capabilities: StateFlow<IoCapabilities> get() = sender.capabilities

    /** The dispatcher's thread: one datagram into the ring; false when it is full (the caller counts it). */
    internal fun put(
        buf: PacketBuffer,
        len: Int,
        from: InetSocketAddress,
        local: InetSocketAddress?,
        ecn: Ecn,
    ): Boolean {
        val t = tail.load()
        if (t - head.load() >= size) return false
        val i = t and (size - 1)
        buf.copyTo(data[i], 0, 0, len)
        lengths[i] = len
        this.from[i] = from
        locals[i] = local
        ecns[i] = ecn
        tail.store(t + 1) // publishes the slot
        putSinceWake = true
        return true
    }

    /** The dispatcher's thread, after a receive round: the loop learns of what this round put. */
    internal fun wake() {
        if (!putSinceWake) return
        putSinceWake = false
        signal.trySend(Unit)
    }

    /** The dispatcher's thread: the shared socket failed; the loop hears it at its next receive, as from a socket of its own. */
    internal fun fail(e: Throwable) {
        failure = e
        signal.trySend(Unit)
    }

    /** The dispatcher's thread: a Packet Too Big the shared socket queued, for this loop's connections to check. */
    internal fun offerPacketTooBig(
        quote: ByteArray,
        len: Int,
        dst: InetSocketAddress,
        mtu: Int,
    ) {
        if (ptbs.trySend(Ptb(quote.copyOf(len), dst, mtu)).isSuccess) {
            putSinceWake = true // the loop takes it even with no datagram
        } else {
            dispatcher.ptbDroppedOne() // the loop has not taken the ones before: as the socket's own ring, newer ones go
        }
    }

    /** The loop's thread: the Packet Too Big messages offered since the last call ([EndpointLoop.drainPacketTooBig]). */
    override fun drainPacketTooBig(sink: (quote: ByteArray, len: Int, dst: InetSocketAddress, mtu: Int) -> Unit) {
        for (k in 0 until KslDatagramIo.PTB_PER_DRAIN) {
            val p = ptbs.tryReceive().getOrNull() ?: return
            sink(p.quote, p.quote.size, p.dst, p.mtu)
        }
    }

    /** The loop's thread: what waits, as far as [into] has room. */
    private fun take(into: PacketBatch): Int {
        var h = head.load()
        val t = tail.load()
        var n = 0
        while (into.count < into.capacity && h != t) {
            val r = h and (size - 1)
            val i = into.count
            val len = lengths[r]
            into.buffer(i).copyFrom(data[r], 0, 0, len)
            into.setLength(i, len)
            into.setAddress(i, from[r]!!)
            into.setLocalAddress(i, locals[r])
            into.setEcn(i, ecns[r])
            h++
            n++
        }
        head.store(h) // the slots read are the dispatcher's again
        return n
    }

    override suspend fun receive(into: PacketBatch): Int {
        if (into.count >= into.capacity) return 0
        holdForTest?.await()
        while (true) {
            if (closed.load() != 0) throw IllegalStateException("datagram io closed")
            failure?.let { throw it }
            val n = take(into)
            // a Packet Too Big waits: an empty round, after which the loop drains it (EndpointLoop.afterReceive)
            @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
            if (n > 0 || !ptbs.isEmpty) return n
            signal.receive() // a wake after the slots it announces were published: none is missed
        }
    }

    override fun receiveNow(
        into: PacketBatch,
        waitMs: Int,
    ): Int {
        if (closed.load() != 0 || failure != null || into.count >= into.capacity || holdForTest != null) return 0
        return take(into)
    }

    override suspend fun send(batch: PacketBatch): Int = sender.send(batch)

    override fun trySend(batch: PacketBatch): Int = sender.trySend(batch)

    override fun disableEcnMarking() = sender.disableEcnMarking()

    /** This loop is done with the socket: its sender closes, and the last inbox to close closes the socket. */
    override fun close() {
        if (!closed.compareAndSet(0, 1)) return
        signal.close(IllegalStateException("datagram io closed"))
        try {
            sender.close()
        } finally {
            dispatcher.inboxClosed()
        }
    }

    init {
        check(size and (size - 1) == 0) { "the ring's size is a power of two" }
    }
}

/** A [LoopInbox] whose sender is the accelerated socket's clone: sends never suspend, EMSGSIZE hints reach the loop. */
internal class AcceleratedLoopInbox(
    dispatcher: SocketDispatcher,
    index: Int,
    sender: DatagramIo,
) : LoopInbox(dispatcher, index, sender),
    NonSuspendingSend {
    override fun takeEmsgsize(): Int = (sender as NonSuspendingSend).takeEmsgsize()
}

/**
 * A loop's sender on a socket that has no send-only clone (a caller-supplied [DatagramIo]): the loops of the group take turns
 * on it under one [lock]. A [trySend] that finds another loop sending sends nothing (its datagrams count as socket drops and
 * loss recovery repairs them); [send] waits its turn.
 */
internal class SerializedSender(
    private val io: DatagramIo,
    private val lock: Mutex,
) : DatagramIo {
    override val localAddress: InetSocketAddress get() = io.localAddress
    override val capabilities: StateFlow<IoCapabilities> get() = io.capabilities

    override suspend fun receive(into: PacketBatch): Int = throw UnsupportedOperationException("a sender does not receive")

    override suspend fun send(batch: PacketBatch): Int = lock.withLock { io.send(batch) }

    override fun trySend(batch: PacketBatch): Int {
        if (!lock.tryLock()) return 0
        try {
            return io.trySend(batch)
        } finally {
            lock.unlock()
        }
    }

    override fun disableEcnMarking() = io.disableEcnMarking()

    /** The shared socket stays: its dispatcher closes it. */
    override fun close() {}
}
