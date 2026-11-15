// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.kuicksilver.annotations.ExperimentalKuicksilverApi::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.http3.fuzz

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.cancel
import io.ktor.utils.io.close
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionStats
import io.kuicksilver.quic.ConnectionTransportHooks
import io.kuicksilver.quic.Datagram
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicPath
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.StreamTransportHooks
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * An in-memory QUIC connection pair for the HTTP/3 fuzzer: streams carry bytes in order, but nothing moves between the
 * two sides until the driver delivers it ([MemNet.deliver]), one queued piece at a time, in any order across streams
 * (QUIC orders data within a stream only). So the fuzzer chooses when each side's QPACK encoder and decoder streams, control
 * streams and request streams arrive, and races a GOAWAY, a reset or a STOP_SENDING against data. Stream limits follow
 * RFC 9000 section 4.6 (a peer stream's credit returns once it is done in both directions and, when held, released), and
 * a STOP_SENDING is answered with RESET_STREAM (section 3.5). Everything runs on the caller's single dispatcher.
 */
internal class MemNet(
    val scope: CoroutineScope,
    bidiLimit: Long,
    uniLimit: Long,
) {
    val client = MemConn(this, isClient = true, bidiLimit, uniLimit)
    val server = MemConn(this, isClient = false, bidiLimit, uniLimit)

    init {
        client.peer = server
        server.peer = client
    }

    /** What is on its way: in the order it was sent, delivered in any order the rules allow. */
    val inflight = ArrayList<Piece>()

    /** Pieces delivered so far, by kind (reach counters). */
    val delivered = HashMap<String, Int>()

    sealed class Piece(
        /** The stream half that receives it. */
        val to: MemStream,
    ) {
        class Data(
            to: MemStream,
            val bytes: ByteArray,
        ) : Piece(to)

        class Fin(
            to: MemStream,
        ) : Piece(to)

        class Reset(
            to: MemStream,
            val code: Long,
        ) : Piece(to)

        /** STOP_SENDING for the sending half [to]. */
        class Stop(
            to: MemStream,
            val code: Long,
        ) : Piece(to)
    }

    /** Pieces that may be delivered now: data and FIN only as the first of their stream half, resets and stops at any time. */
    fun deliverable(): List<Piece> {
        val seen = HashSet<MemStream>()
        val out = ArrayList<Piece>()
        for (p in inflight) {
            when (p) {
                is Piece.Data, is Piece.Fin -> if (seen.add(p.to)) out += p
                else -> out += p
            }
        }
        return out
    }

    fun deliver(p: Piece) {
        inflight.remove(p)
        delivered[p::class.simpleName!!] = (delivered[p::class.simpleName!!] ?: 0) + 1
        val s = p.to
        if (s.conn.isClosed) return
        s.conn.announce(s)
        when (p) {
            is Piece.Data -> {
                s.received(p.bytes)
            }

            is Piece.Fin -> {
                s.receivedFin()
            }

            is Piece.Reset -> {
                // RESET_STREAM: what had not arrived is discarded (RFC 9000 section 3.2)
                inflight.removeAll { (it is Piece.Data || it is Piece.Fin) && it.to === s }
                s.receivedReset(p.code)
            }

            is Piece.Stop -> {
                s.receivedStop(p.code)
            }
        }
    }

    /** Everything that can be delivered, until nothing is left (pieces sent meanwhile included), at most [max] pieces. */
    fun deliverAll(max: Int = 100_000): Int {
        var n = 0
        while (n < max) {
            val p = deliverable().firstOrNull() ?: break
            deliver(p)
            n++
        }
        return n
    }

    val stats: ConnectionStats by lazy { emptyStats() }
}

/** A [ConnectionStats] of zeros through its constructor (internal to the transport module), for [MemConn.stats]. */
private fun emptyStats(): ConnectionStats {
    val c = ConnectionStats::class.java.declaredConstructors.maxBy { it.parameterCount }
    c.isAccessible = true
    val args =
        c.parameterTypes
            .map { t ->
                when {
                    t == java.lang.Long.TYPE -> 0L
                    t == Integer.TYPE -> 0
                    t == java.lang.Boolean.TYPE -> false
                    t == java.lang.Double.TYPE -> 0.0
                    t.isEnum -> t.enumConstants[0]
                    else -> null
                }
            }.toTypedArray()
    return c.newInstance(*args) as ConnectionStats
}

internal class MemConn(
    val net: MemNet,
    val isClient: Boolean,
    bidiLimit: Long,
    uniLimit: Long,
) : QuicConnection,
    ConnectionTransportHooks {
    lateinit var peer: MemConn
    private val streams = HashMap<Long, MemStream>()
    private val accept = Channel<MemStream>(Channel.UNLIMITED)

    /** [0] bidi, [1] uni: streams we opened, and how many the peer allows us in total. */
    private val opened = longArrayOf(0, 0)
    val allowed = arrayOf(MutableStateFlow(bidiLimit), MutableStateFlow(uniLimit))

    /** What we granted the peer: its streams that are done (and released when held) raise it. */
    val granted = longArrayOf(bidiLimit, uniLimit)

    var holdBidi = false
    val held = HashSet<Long>()
    private val due = HashSet<Long>()
    private val closedDeferred = CompletableDeferred<QuicException.ConnectionLost>()
    val isClosed: Boolean get() = closedDeferred.isCompleted

    /** Peer streams that are not done, and our own: the transport's state, for the leak check at quiesce. */
    val liveStreams: Collection<MemStream> get() = streams.values.filter { !it.done.isCompleted }

    /** The highest peer stream id seen, per type: a peer stream past the limit we granted is a finding. */
    var peerStreamsBeyondLimit = 0

    fun stream(id: Long): MemStream = streams.getOrPut(id) { MemStream(this, id) }

    /** A peer stream becomes visible to [acceptStream] when its first piece arrives (lower ones of its kind open with it). */
    fun announce(s: MemStream) {
        if (s.announced || s.local) return
        val type = if (s.bidi) 0 else 1
        if (s.id / 4 >= granted[type]) peerStreamsBeyondLimit++
        var id = s.id and 3L
        while (id <= s.id) {
            val x = stream(id)
            if (!x.announced) {
                x.announced = true
                if (holdBidi && x.bidi) held += x.id
                accept.trySend(x)
            }
            id += 4
        }
    }

    /** Stream [s] is done in both directions: a peer stream's credit returns (now, or at its release when held). */
    fun finished(s: MemStream) {
        if (s.local) return
        if (s.id in held) {
            due += s.id
            return
        }
        returnCredit(s)
    }

    private fun returnCredit(s: MemStream) {
        val type = if (s.bidi) 0 else 1
        granted[type]++
        peer.allowed[type].value = granted[type]
    }

    fun release(s: MemStream) {
        if (!held.remove(s.id)) return
        if (due.remove(s.id)) returnCredit(s)
    }

    override fun holdPeerStreamCreditHook() {
        if (holdBidi) return
        holdBidi = true
        for (s in streams.values) if (!s.local && s.bidi && s.announced && !s.done.isCompleted) held += s.id
    }

    override val peerBidiStreamsGrantedHook: Long get() = granted[0]
    override val localBidiStreamsAllowedHook: Long get() = allowed[0].value

    private suspend fun open(bidi: Boolean): QuicStream {
        val type = if (bidi) 0 else 1
        allowed[type].first { opened[type] < it || isClosed }
        if (isClosed) throw closedDeferred.getCompleted()
        val id = opened[type]++ * 4 + (if (isClient) 0 else 1) + (if (bidi) 0 else 2)
        return stream(id).also { it.startPump() }
    }

    override suspend fun openBidi(priority: StreamPriority): QuicStream = open(true)

    override suspend fun openUni(priority: StreamPriority): QuicStream = open(false)

    override suspend fun acceptStream(): QuicStream =
        accept.receiveCatching().getOrNull()?.also { it.startPump() } ?: throw closedDeferred.getCompleted()

    override val stats: ConnectionStats get() = net.stats
    override val peerCertificates: List<Certificate> get() = emptyList()
    override val negotiatedAlpn: String get() = "h3"
    private val path =
        object : QuicPath {
            override val id: io.kuicksilver.quic.PathId = io.kuicksilver.quic.PathId.Initial
            override val localAddress =
                io.ktor.network.sockets
                    .InetSocketAddress(if (isClient) "10.0.0.1" else "10.0.0.2", 443)
            override val remoteAddress =
                io.ktor.network.sockets
                    .InetSocketAddress(if (isClient) "10.0.0.2" else "10.0.0.1", 443)
            override val state: StateFlow<io.kuicksilver.quic.PathState> =
                MutableStateFlow(
                    io.kuicksilver.quic.PathState.entries
                        .first(),
                )

            override suspend fun probe(): Boolean = false

            override suspend fun switchTo() {}

            override fun close() {}
        }
    override val paths: List<QuicPath> get() = listOf(path)
    override val pathEvents: Flow<PathEvent> get() = emptyFlow()

    override suspend fun addPath(io: DatagramIo): QuicPath = throw UnsupportedOperationException()

    override suspend fun migrate(newIo: DatagramIo): PathEvent.Changed = throw UnsupportedOperationException()

    override suspend fun sendDatagram(
        data: ByteArray,
        policy: DatagramPolicy,
    ): Unit = throw UnsupportedOperationException("no datagrams")

    override fun trySendDatagram(
        data: ByteArray,
        policy: DatagramPolicy,
    ): DatagramSendResult = throw UnsupportedOperationException("no datagrams")

    override val datagrams: Flow<Datagram> get() = emptyFlow()
    override val maxDatagramSize: StateFlow<Int> = MutableStateFlow(0)
    override val peerSupportsDatagrams: Boolean get() = false

    override suspend fun keyUpdate() {}

    override suspend fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray = ByteArray(length)

    /** CONNECTION_CLOSE reaches the peer at once: the fuzzer races it against streams through the pieces still queued. */
    override suspend fun close(
        code: Long,
        reason: String,
    ) {
        closeNow(code, reason)
    }

    fun closeNow(
        code: Long,
        reason: String,
    ) {
        closeWith(QuicException.ConnectionLost.ApplicationClosed(code, reason, Initiator.Local))
        peer.closeWith(QuicException.ConnectionLost.ApplicationClosed(code, reason, Initiator.Peer))
    }

    fun closeWith(e: QuicException.ConnectionLost) {
        if (!closedDeferred.complete(e)) return
        accept.close(e)
        for (s in streams.values) s.connectionLost(e)
        for (a in allowed) a.value = a.value // openers recheck isClosed
        allowed[0].value = Long.MAX_VALUE
        allowed[1].value = Long.MAX_VALUE
    }

    override val closed: Deferred<QuicException.ConnectionLost> get() = closedDeferred
    override val core: ConnectionCore get() = throw UnsupportedOperationException("in-memory transport")

    override fun close() {
        closeNow(0, "")
    }
}

internal class MemStream(
    val conn: MemConn,
    override val id: Long,
) : QuicStream,
    StreamTransportHooks {
    val bidi = id and 2L == 0L
    val local = (id and 1L == 0L) == conn.isClient
    private val hasRecv = bidi || !local
    private val hasSend = bidi || local
    var announced = local
    private val inCh = ByteChannel()
    private val outCh = ByteChannel()
    override val input: ByteReadChannel get() = inCh
    override val output: ByteWriteChannel get() = outCh
    override var priority: StreamPriority = StreamPriority.Default

    /** The same stream on the other side. */
    private val other: MemStream get() = conn.peer.stream(id)
    private val feed = Channel<ByteArray?>(Channel.UNLIMITED)
    private var recvDone = !hasRecv
    private var sendDone = !hasSend
    private var recvAll = false
    val done = CompletableDeferred<Unit>()
    private var pumping = false

    init {
        if (!hasRecv) inCh.close()
        if (!hasSend) outCh.close()
        // the writer of what arrives: in order, waiting while the reader lags (flow control in the small)
        if (hasRecv) {
            conn.net.scope.launch {
                try {
                    for (b in feed) {
                        if (b == null) {
                            inCh.flushAndClose()
                            recvAll = true
                            recvDone = true
                            check()
                            break
                        }
                        inCh.writeFully(b)
                        inCh.flush()
                    }
                } catch (_: Throwable) {
                    // the reader stopped or the stream was reset: the rest is dropped
                }
            }
        }
    }

    /** Copies what HTTP/3 writes into pieces for the peer; started once the stream is opened or handed out. */
    fun startPump() {
        if (pumping || !hasSend) return
        pumping = true
        conn.net.scope.launch {
            val buf = ByteArray(4096)
            try {
                while (true) {
                    val n = outCh.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    if (n > 0 && !sendDone) conn.net.inflight += MemNet.Piece.Data(other, buf.copyOf(n))
                }
                if (outCh.closedCause == null && !sendDone) {
                    // done once the FIN arrived (it stands for everything acknowledged, RFC 9000 "Data Recvd")
                    conn.net.inflight += MemNet.Piece.Fin(other)
                }
            } catch (_: Throwable) {
                // reset or stopped: the reset piece is queued where that happened
            }
        }
    }

    override fun reset(code: Long) {
        // nothing to send, all of it sent (FIN), or already reset or stopped
        if (sendDone || !hasSend || conn.isClosed) return
        sendDone = true
        outCh.cancel(QuicException.StreamError.Reset(id, code, Initiator.Local))
        conn.net.inflight.removeAll { (it is MemNet.Piece.Data || it is MemNet.Piece.Fin) && it.to === other }
        conn.net.inflight += MemNet.Piece.Reset(other, code)
        check()
    }

    override fun stopSending(code: Long) {
        if (recvDone || !hasRecv || conn.isClosed) return
        inCh.cancel(QuicException.StreamError.Stopped(id, code, Initiator.Local))
        feed.close()
        conn.net.inflight += MemNet.Piece.Stop(other, code)
    }

    fun received(bytes: ByteArray) {
        feed.trySend(bytes)
    }

    /** Our FIN reached the peer: everything we sent arrived (the sending half's "Data Recvd"). */
    fun finArrived() {
        if (sendDone) return
        sendDone = true
        check()
    }

    fun receivedFin() {
        other.finArrived()
        // after our STOP_SENDING the FIN still ends the half: the peer had sent everything (RFC 9000 section 3.2, "Data Recvd")
        if (feed.trySend(null).isFailure && !recvDone) {
            recvAll = true
            recvDone = true
            check()
        }
    }

    fun receivedReset(code: Long) {
        feed.close()
        if (!inCh.isClosedForWrite) inCh.cancel(QuicException.StreamError.Reset(id, code, Initiator.Peer))
        recvDone = true
        check()
    }

    /** The peer's STOP_SENDING: our sending half fails, and a RESET_STREAM follows (RFC 9000 section 3.5). */
    fun receivedStop(code: Long) {
        if (sendDone) return
        sendDone = true
        outCh.cancel(QuicException.StreamError.Stopped(id, code, Initiator.Peer))
        conn.net.inflight.removeAll { (it is MemNet.Piece.Data || it is MemNet.Piece.Fin) && it.to === other }
        conn.net.inflight += MemNet.Piece.Reset(other, code)
        check()
    }

    fun connectionLost(e: QuicException.ConnectionLost) {
        feed.close()
        if (!inCh.isClosedForWrite) inCh.cancel(e)
        if (!outCh.isClosedForWrite) outCh.cancel(e)
        done.complete(Unit)
    }

    private fun check() {
        if (recvDone && sendDone && done.complete(Unit)) conn.finished(this)
    }

    override fun releaseStreamCreditHook() {
        conn.release(this)
    }

    override suspend fun awaitFinishedHook() {
        done.await()
    }

    override val receivedAllHook: Boolean get() = recvAll
}
