// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.ConnectionCore
import io.kuicksilver.quic.ConnectionEvent
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.ConnectionStats
import io.kuicksilver.quic.Datagram
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.DatagramUnsupportedReason
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicPath
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.VerifyReason
import io.kuicksilver.tls.VerifyResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.Volatile

/** The runtime half of one connection: events → deferreds and channels, application calls → commands on the loop. */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ConnectionRuntime(
    private val loop: EndpointLoop,
    override val core: ConnectionCore,
) : QuicConnection {
    internal val handshake = CompletableDeferred<Unit>()
    private val closedDeferred = CompletableDeferred<QuicException.ConnectionLost>()
    override val closed: Deferred<QuicException.ConnectionLost> get() = closedDeferred
    private val accepted = Channel<QuicStream>(Channel.UNLIMITED)
    private val streams = HashMap<Long, StreamRuntime>()

    /** Signalled after every poll: writers and stream openers retry. */
    private val tickers = ArrayList<Channel<Unit>>()

    /** Tickers of [open] calls waiting for the peer's stream limit; StreamsAvailable wakes them. */
    private val openWaiters = ArrayList<Channel<Unit>>()
    internal var serverSide = false

    /** Server: handed to the accept queue (at 0-RTT acceptance or at handshake completion). Loop dispatcher only. */
    internal var handedOff = false

    @Volatile private var earlyAccepted: Boolean? = null
    override val earlyDataAccepted: Boolean? get() = earlyAccepted

    override suspend fun awaitHandshake() {
        handshake.await()
    }

    override val isHandshakeComplete: Boolean get() = handshake.isCompleted && !handshake.isCancelled

    /** A server connection still handshaking, counted by its loop against the accept queue. Loop dispatcher only. */
    internal var handshaking = false

    @Volatile private var finished = false

    @Volatile private var certificates: List<Certificate> = emptyList()

    /** Live stream wrappers (test hook): finished streams leave the map. */
    internal val streamCountForTest: Int get() = streams.size
    internal val tickerCountForTest: Int get() = tickers.size
    internal val pathCountForTest: Int get() = pathList.size
    internal val streamIdsForTest: List<Long> get() = streams.keys.toList()

    internal val role = core.role

    /** What a [io.kuicksilver.quic.ConnectionListener] and the logger know this connection by: its original DCID in hex (its qlog name). */
    internal val info: io.kuicksilver.quic.ConnectionInfo =
        io.kuicksilver.quic.ConnectionInfo(core.odcid.toString(), role, this) { core.remoteAddress }

    /** The 0-RTT outcome went to the observer already (loop dispatcher only). */
    internal var zeroRttReported = false

    // ---- paths ----

    /** The path the connection sends on, as last seen by the loop (any thread reads it; the loop re-checks before acting). */
    @Volatile internal var activePathId: PathId = PathId.Initial
        private set

    /** Copy-on-write: mutated on the loop, read from application threads through [paths]. */
    @Volatile private var pathList: List<PathRuntime> = listOf(PathRuntime(this, loop, PathId.Initial, loop.localAddress, null))
    private val pathEventFlow = MutableSharedFlow<PathEvent>(extraBufferCapacity = 64)
    override val paths: List<QuicPath> get() = pathList.filter { it.stateFlow.value != PathState.Closed }
    override val pathEvents: Flow<PathEvent> get() = pathEventFlow

    private fun pathRuntime(id: PathId): PathRuntime =
        pathList.firstOrNull {
            it.id == id
        } ?: PathRuntime(this, loop, id, loop.localAddress, null).also {
            pathList = pathList + it
        } // a path the peer moved to (server side) shares the endpoint's socket

    override suspend fun addPath(io: DatagramIo): QuicPath {
        var adopted = false // set on the loop once a path owns io; until then every way out (failure, cancellation) closes it
        try {
            return withContext(loop.dispatcher) {
                if (finished) throw closedDeferred.await()
                // connect() returns at handshake completion; migration needs the confirmation that follows within one round trip (RFC 9000 section 9)
                if (core.state !=
                    ConnectionState.Confirmed
                ) {
                    val ticker = newTicker()
                    try {
                        while (core.state !=
                            ConnectionState.Confirmed
                        ) {
                            if (finished) throw closedDeferred.await()
                            ticker.receive()
                        }
                    } finally {
                        removeTicker(ticker)
                    }
                }
                val id = core.addPath(core.remoteAddress, loop.now())
                core.setPathCapabilities(id, io.capabilities.value)
                val rt = PathRuntime(this@ConnectionRuntime, loop, id, io.localAddress, io)
                pathList = pathList + rt
                rt.receiver = loop.receiveOn(io, core, id)
                adopted = true
                rt
            }
        } finally {
            if (!adopted) io.close()
        }
    }

    override suspend fun migrate(newIo: DatagramIo): PathEvent.Changed {
        val p = addPath(newIo)
        if (!p.probe()) {
            withContext(loop.dispatcher) { closePath(p as PathRuntime) }
            throw IllegalStateException("path validation failed")
        }
        val old = withContext(loop.dispatcher) { pathRuntime(core.path.id) }
        p.switchTo()
        return PathEvent.Changed(old, p, PathChangeReason.ActiveMigration)
    }

    /** Loop dispatcher only; never called for the active path. */
    internal fun closePath(p: PathRuntime) {
        if (core.pathState(p.id) != PathState.Closed &&
            core.path.id != p.id
        ) {
            core.closePath(p.id)
        }
        p.receiver?.cancel()
        p.io?.close()
        p.stateFlow.value = PathState.Closed
        pathList =
            pathList - p
        if (!p.validation.isCompleted) p.validation.complete(false)
    }

    private fun onPathEvent(e: ConnectionEvent) {
        when (e) {
            is ConnectionEvent.PathValidated -> {
                loop.observer.pathValidated(this, true)
                val p = pathRuntime(e.path)
                p.stateFlow.value = PathState.Validated
                if (!p.validation.isCompleted) p.validation.complete(true)
                pathEventFlow.tryEmit(PathEvent.Validated(p))
            }

            is ConnectionEvent.PathFailed -> {
                loop.observer.pathValidated(this, false)
                val p = pathRuntime(e.path)
                p.stateFlow.value = PathState.Failed
                if (!p.validation.isCompleted) p.validation.complete(false)
                pathEventFlow.tryEmit(PathEvent.Failed(p))
            }

            is ConnectionEvent.PathChanged -> {
                activePathId = e.new
                val o = pathRuntime(e.old)
                val n = pathRuntime(e.new)
                o.stateFlow.value =
                    core.pathState(e.old)
                n.stateFlow.value = core.pathState(e.new)
                val change = PathEvent.Changed(o, n, e.reason)
                pathEventFlow.tryEmit(change)
                loop.observer.pathChanged(this, change)
            }

            else -> {
                return
            }
        }
        prunePaths()
    }

    /**
     * Closes the runtimes of paths the core dropped to make room for a new one (at most four paths, the oldest that is
     * neither active nor last validated nor under validation goes): without this a server whose peer keeps moving would
     * keep one runtime per address it ever saw. Loop dispatcher only.
     */
    private fun prunePaths() {
        for (p in pathList) if (p.id != activePathId && core.paths.byId(p.id) == null) closePath(p)
    }

    // ---- datagrams (RFC 9221) ----
    private val sendQueue =
        DatagramSendQueue(core.config.datagramSendQueue, core.config.datagramSendQueueBytes).also {
            core.datagramSender =
                it
        }

    /** Datagrams buffered on the send side (commands not yet applied plus the queue), as seen from any thread (test hook). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val datagramsQueuedForTest: Int get() = sendQueue.count.load()
    private val maxDatagramSizeFlow = MutableStateFlow(0)
    override val maxDatagramSize: StateFlow<Int> get() = maxDatagramSizeFlow
    private val datagramSignal = Channel<Unit>(Channel.CONFLATED)

    /** Applies queued send commands on the loop and flushes; one coroutine per connection, woken per burst. */
    private val datagramDrainer: Job =
        loop.scope.launch {
            try {
                for (u in sendQueue.signal) {
                    while (true) {
                        val added = sendQueue.applyCommands()
                        if (added || !sendQueue.isEmpty) loop.flush(core) // let the core send what the window allows
                        if (!sendQueue.hasPendingCommands) break
                        // the network did not take them: the policy decides who goes
                        if (sendQueue.isFull) sendQueue.evictForPending() else kotlinx.coroutines.yield()
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (!finished) core.failInternal(e)
            }
        }

    private fun datagramPrecheck(size: Int): DatagramSendResult? {
        if (core.config.maxDatagramFrameSize == 0L) return DatagramSendResult.Unsupported(DatagramUnsupportedReason.Disabled)
        val max = maxDatagramSizeFlow.value
        if (max <=
            0
        ) {
            return DatagramSendResult.Unsupported(DatagramUnsupportedReason.PeerDoesNotSupport)
        }
        if (size > max) return DatagramSendResult.TooLarge(max)
        return null
    }

    override fun trySendDatagram(
        data: ByteArray,
        policy: DatagramPolicy,
    ): DatagramSendResult {
        datagramPrecheck(data.size)?.let { return it }
        // not QueueFull: a caller retrying on that would spin; a try-method answers instead of throwing
        if (finished) return DatagramSendResult.Closed
        if (policy === DatagramPolicy.Reject && !sendQueue.hasRoom(data.size)) return DatagramSendResult.QueueFull
        sendQueue.offer(data.copyOf(), policy)
        return DatagramSendResult.Sent
    }

    override suspend fun sendDatagram(
        data: ByteArray,
        policy: DatagramPolicy,
    ) {
        when (val r = datagramPrecheck(data.size)) {
            is DatagramSendResult.TooLarge -> {
                throw QuicException.DatagramTooLarge(data.size, r.max)
            }

            is DatagramSendResult.Unsupported -> {
                throw QuicException.DatagramUnsupported(r.reason)
            }

            else -> {}
        }
        if (policy === DatagramPolicy.Reject && !sendQueue.hasRoom(data.size)) {
            withContext(loop.dispatcher) {
                val ticker = newTicker()
                try {
                    while (!sendQueue.hasRoom(data.size)) {
                        if (finished) throw closedDeferred.await()
                        ticker.receive()
                    }
                } finally {
                    removeTicker(ticker)
                }
            } // every poll ticks: datagrams leave, room returns
        }
        if (finished) throw closedDeferred.await()
        sendQueue.offer(data.copyOf(), policy)
    }

    /** Pull-based: the core's own 128-entry queue is the only buffer, so what nobody collects is dropped there and counted. */
    override val datagrams: Flow<Datagram> get() =
        flow {
            val buf = ByteArray(65_535)
            while (true) {
                val n = withContext(loop.dispatcher) { if (finished) -2 else core.readDatagram(buf, 0) }
                if (n == -2) throw closedDeferred.await()
                if (n >= 0) {
                    emit(Datagram(buf.copyOf(n)))
                } else if (datagramSignal.receiveCatching().isClosed) {
                    throw closedDeferred.await() // failed() closes the signal without a cause
                }
            }
        }

    private fun isLocal(id: Long) = (id and 1L == 0L) == (role == io.kuicksilver.tls.TlsRole.Client)

    internal fun drainEvents() {
        val max = core.maxDatagramPayload
        if (max != maxDatagramSizeFlow.value) maxDatagramSizeFlow.value = max
        core.datagramsDroppedSend = sendQueue.dropped
        while (true) {
            val e = core.nextEvent() ?: break
            when (e) {
                ConnectionEvent.HandshakeCompleted -> {
                    earlyAccepted = core.earlyDataAccepted
                    certificates = core.peerCertificates // read once, on the loop: the TLS object is not shared across threads
                    handshake.complete(Unit)
                    loop.observer.handshakeCompleted(this)
                    loop.onHandshakeCompleted(this)
                }

                is ConnectionEvent.VerifyRequested -> {
                    loop.scope.launch(Dispatchers.Default) { verify(e) }
                }

                is ConnectionEvent.SessionTicket -> {
                    loop.storeTicket(core.tlsConfig, e.ticket)
                }

                ConnectionEvent.EarlyDataAccepted -> {
                    earlyAccepted = true
                    loop.observer.zeroRtt(this, io.kuicksilver.quic.ZeroRttOutcome.Accepted)
                    alpn = core.negotiatedAlpn // read on the loop: an early-accepted connection reaches accept() before completion
                    // a server hands the connection to accept() now: the application can answer in 0.5-RTT (ADR-0015)
                    if (serverSide) loop.onHandshakeCompleted(this)
                }

                ConnectionEvent.EarlyDataRejected -> {
                    earlyAccepted = false
                    loop.observer.zeroRtt(this, io.kuicksilver.quic.ZeroRttOutcome.Rejected)
                }

                is ConnectionEvent.StreamOpened -> {
                    accepted.trySend(stream(e.id).also { it.receivedEarly = core.streamReceivedEarly(e.id) })
                }

                is ConnectionEvent.StreamReadable -> {
                    streams[e.id]?.signalReadable()
                }

                is ConnectionEvent.StreamWritable -> {
                    streams[e.id]?.ticker?.trySend(Unit) // the broadcast tick after each flush stays as the fallback
                }

                is ConnectionEvent.StreamReset -> {
                    streams[e.id]?.peerReset(e.code)
                    core.readStream(e.id, NO_BYTES, 0, 0)
                }

                // the reset is surfaced: acknowledge it in the core (ResetRecvd -> ResetRead) so the half retires, MAX_STREAMS credit returns and StreamFinished follows
                is ConnectionEvent.StopSendingReceived -> {
                    streams[e.id]?.peerStopped(e.code)
                }

                is ConnectionEvent.StreamFinished -> {
                    streams.remove(e.id)?.finished()
                }

                // both halves done and consumed: the wrapper and its ticker go
                is ConnectionEvent.StreamsAvailable -> {
                    for (t in openWaiters) t.trySend(Unit)
                }

                is ConnectionEvent.Closed -> {
                    failed(e.reason)
                }

                is ConnectionEvent.PathValidated, is ConnectionEvent.PathFailed, is ConnectionEvent.PathChanged -> {
                    onPathEvent(e)
                }

                ConnectionEvent.DatagramsReadable -> {
                    datagramSignal.trySend(Unit)
                }

                is ConnectionEvent.MtuUpdated -> {} // maxDatagramSize follows through the check at the top of drainEvents
            }
        }
    }

    /**
     * Runs the (possibly application-supplied) verifier off the loop. A verifier that throws rejects the peer; a result that
     * arrives after the connection ended (handshake timeout, close) is dropped: the TLS session is already freed.
     */
    private suspend fun verify(e: ConnectionEvent.VerifyRequested) {
        val r =
            try {
                e.session.verifyPeer(e.chain)
            } catch (
                c: CancellationException,
            ) {
                throw c
            } catch (
                t: Throwable,
            ) {
                VerifyResult.Rejected(VerifyReason.Custom("verifier failed: ${t.message ?: t::class.simpleName}"))
            }
        withContext(loop.dispatcher) {
            if (finished || core.state == ConnectionState.Closing || core.state == ConnectionState.Draining ||
                core.state == ConnectionState.Closed
            ) {
                return@withContext
            }
            try {
                core.resumeVerify(r)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                core.failInternal(t)
            }
            loop.flush(core)
        }
    }

    internal fun tick() {
        for (t in tickers) t.trySend(Unit)
    }

    internal fun finish() {
        if (!finished) failed(QuicException.ConnectionLost.Internal("connection finished", null))
    }

    internal fun failed(reason: QuicException.ConnectionLost) {
        if (finished) return
        finished = true
        loop.observer.closed(this, reason, handshakeDone = handshake.isCompleted && !handshake.isCancelled)
        closedDeferred.complete(reason)
        handshake.completeExceptionally(reason)
        accepted.close(reason)
        for (s in streams.values) s.connectionLost(reason)
        for (p in pathList) {
            p.receiver?.cancel()
            p.io?.close()
            if (!p.validation.isCompleted) p.validation.complete(false)
        }
        datagramDrainer.cancel()
        sendQueue.close()
        datagramSignal.close()
        // every waiter (open, flush, keyUpdate, addPath, sendDatagram) wakes with the connection's own reason
        for (t in tickers) t.close(reason)
    }

    private fun stream(
        id: Long,
        priority: StreamPriority = StreamPriority.Default,
    ): StreamRuntime =
        streams.getOrPut(id) {
            StreamRuntime(
                this,
                loop,
                id,
                recv =
                    (id and 2L == 0L) || !isLocal(id),
                send = (id and 2L == 0L) || isLocal(id),
                initialPriority = priority,
            )
        }

    internal fun newTicker(): Channel<Unit> = Channel<Unit>(Channel.CONFLATED).also { tickers += it }

    internal fun removeTicker(t: Channel<Unit>) {
        tickers.remove(t)
        t.close()
    }

    private suspend fun open(
        bidi: Boolean,
        priority: StreamPriority,
    ): QuicStream =
        withContext(loop.dispatcher) {
            val ticker = newTicker()
            openWaiters += ticker
            try {
                while (true) {
                    if (finished) throw closedDeferred.await()
                    val id = core.openStream(bidi, priority)
                    if (id >= 0) {
                        val s = stream(id, priority)
                        loop.flush(core)
                        return@withContext s
                    }
                    ticker.receive()
                }
                @Suppress("UNREACHABLE_CODE")
                throw IllegalStateException()
            } finally {
                tickers.remove(ticker)
                openWaiters.remove(ticker)
            }
        }

    override suspend fun openBidi(priority: StreamPriority): QuicStream = open(true, priority)

    override suspend fun openUni(priority: StreamPriority): QuicStream = open(false, priority)

    override suspend fun acceptStream(): QuicStream = accepted.receive()

    override val stats: ConnectionStats get() = core.stats
    override val peerCertificates: List<Certificate> get() = certificates

    @Volatile private var alpn: String? = null
    override val negotiatedAlpn: String? get() = alpn ?: core.negotiatedAlpn

    override suspend fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray =
        withContext(loop.dispatcher) {
            if (finished) throw closedDeferred.await()
            core.exportKeyingMaterial(label, context, length)
        }

    override suspend fun keyUpdate() {
        withContext(loop.dispatcher) {
            val ticker = newTicker()
            try {
                while (!core.initiateKeyUpdate(loop.now())) {
                    if (finished) throw closedDeferred.await()
                    ticker.receive()
                }
                loop.flush(core)
            } finally {
                removeTicker(ticker)
            } // every poll ticks: ACKs arrive, confirmation happens
        }
    }

    override suspend fun close(
        code: Long,
        reason: String,
    ) {
        withContext(loop.dispatcher) {
            core.close(code, reason, loop.now())
            loop.flush(core)
        }
    }

    override fun close() {
        loop.scope.launch { close(0, "") }
    }

    internal fun defaultCode(): Long = core.config.defaultStreamErrorCode

    private companion object {
        val NO_BYTES = ByteArray(0)
    }
}
