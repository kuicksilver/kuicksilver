// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
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
import io.kuicksilver.quic.PathFailureReason
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.PathValidationException
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicPath
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.SocketDefunctException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.core.failInternal
import io.kuicksilver.quic.core.silentClose
import io.kuicksilver.quic.core.takeReceivedTokens
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.VerifyReason
import io.kuicksilver.tls.VerifyResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.concurrent.Volatile

/** The runtime half of one connection: events → deferreds and channels, application calls → commands on the loop. */
@OptIn(ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
internal class ConnectionRuntime(
    private val loop: EndpointLoop,
    override val core: ConnectionCore,
) : QuicConnection {
    internal val handshake = CompletableDeferred<Unit>()
    private val closedDeferred = CompletableDeferred<QuicException.ConnectionLost>()
    override val closed: Deferred<QuicException.ConnectionLost> get() = closedDeferred

    /**
     * Peer streams waiting for acceptStream; at most the stream limits we granted, as none of them is counted closed before it is
     * handed out. A stream taken by an acceptStream caller cancelled while being resumed goes back to the queue (at its end), so
     * an application polling acceptStream under a timeout gets it from its next call; the channel is only ever closed, never
     * cancelled, and trySend is lock-free. Once it is closed (the connection ended) [abandonUndelivered] gives the stream up.
     */
    private val accepted: Channel<StreamRuntime> =
        Channel(Channel.UNLIMITED, onUndeliveredElement = { if (!requeue(it)) abandonUndelivered(it) })

    private fun requeue(s: StreamRuntime): Boolean = accepted.trySend(s).isSuccess

    internal val streams = HashMap<Long, StreamRuntime>() // internal for the resource probe

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

    /** The loop's dispatcher (tests that order work against the loop). */
    internal val loopDispatcherForTest: CoroutineDispatcher get() = loop.dispatcher
    internal val tickerCountForTest: Int get() = tickers.size
    internal val pathCountForTest: Int get() = pathList.size
    internal val streamIdsForTest: List<Long> get() = streams.keys.toList()

    internal val role = core.role

    /** What a [io.kuicksilver.quic.ConnectionListener] and the logger know this connection by: its original DCID in hex (its qlog name). */
    internal val info: io.kuicksilver.quic.ConnectionInfo =
        io.kuicksilver.quic.ConnectionInfo(core.odcid.toString(), role, this) { core.remoteAddress }

    /** The 0-RTT outcome went to the observer already (loop dispatcher only). */
    internal var zeroRttReported = false

    init {
        core.qlog?.onFailure = { e -> loop.observer.qlogFailed(this, e) } // LogLevel.Warn: a failing qlog sink
    }

    // ---- paths ----

    /** The path the connection sends on, as last seen by the loop (any thread reads it; the loop re-checks before acting). */
    @Volatile internal var activePathId: PathId = PathId.Initial
        private set

    /** Copy-on-write: mutated on the loop, read from application threads through [paths]. */
    @Volatile private var pathList: List<PathRuntime> =
        listOf(PathRuntime(this, loop, PathId.Initial, loop.localAddress, null, core.remoteAddress))
    private val pathEventFlow = MutableSharedFlow<PathEvent>(extraBufferCapacity = 64)
    override val paths: List<QuicPath> get() = pathList.filter { it.stateFlow.value != PathState.Closed }
    override val pathEvents: Flow<PathEvent> get() = pathEventFlow

    private fun pathRuntime(id: PathId): PathRuntime =
        pathList.firstOrNull {
            it.id == id
        } ?: PathRuntime(this, loop, id, loop.localAddress, null, lastRemote(id)).also {
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
                val rt = PathRuntime(this@ConnectionRuntime, loop, id, io.localAddress, io, core.remoteAddress)
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
            val reason =
                withContext(loop.dispatcher) {
                    closePath(p as PathRuntime)
                    p.failureReason
                }
            throw PathValidationException(reason ?: PathFailureReason.ValidationTimeout)
        }
        val old = withContext(loop.dispatcher) { pathRuntime(core.path.id) }
        p.switchTo()
        return PathEvent.Changed(old, p, PathChangeReason.ActiveMigration)
    }

    /**
     * Suspends until the peer gave us a connection ID no path used yet (RFC 9000 section 9.5), so a new path can be probed; throws the
     * connection's [QuicException.ConnectionLost] once it is gone. [NetworkMigrator] waits here after a
     * [PathFailureReason.NoSpareConnectionId] failure, then migrates again.
     */
    internal suspend fun awaitSpareConnectionId() {
        withContext(loop.dispatcher) {
            val ticker = newTicker()
            try {
                while (true) {
                    if (finished) throw closedDeferred.await()
                    if (core.cids.hasSparePeer()) return@withContext
                    ticker.receive()
                }
            } finally {
                removeTicker(ticker)
            }
        }
    }

    /**
     * The socket [io] is gone (null: the endpoint's own): each live path on it reports [PathEvent.SocketLost] once. The paths
     * stay (the active one cannot go before a move); the loop no longer touches the socket. A client whose active path lost its
     * socket before the handshake is confirmed ends at once with [QuicException.ConnectionLost.NoViablePath]: it may not migrate
     * yet (RFC 9000 section 9) and can neither send its Finished nor receive HANDSHAKE_DONE, so only the idle timeout would end
     * it. Loop dispatcher only.
     */
    internal fun onSocketLost(
        io: DatagramIo?,
        cause: SocketDefunctException,
    ) {
        if (finished) return
        for (p in pathList) {
            if (p.io !== io || p.socketLost || p.stateFlow.value == PathState.Closed) continue
            p.socketLost = true
            pathEventFlow.tryEmit(PathEvent.SocketLost(p, cause))
        }
        val unconfirmed = core.state == ConnectionState.Handshaking || core.state == ConnectionState.Established
        if (role == TlsRole.Client && unconfirmed && pathList.any { it.id == core.path.id && it.socketLost }) {
            core.silentClose(QuicException.ConnectionLost.NoViablePath())
            drainEvents()
        }
    }

    /** Loop dispatcher only; never called for the active path. */
    internal fun closePath(p: PathRuntime) {
        if (core.pathState(p.id) != PathState.Closed &&
            core.path.id != p.id
        ) {
            core.closePath(p.id)
        }
        p.receiver?.cancel()
        p.io?.let {
            it.close()
            loop.forgetDefunct(it)
        }
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
                p.failureReason = e.reason
                if (!p.validation.isCompleted) p.validation.complete(false)
                pathEventFlow.tryEmit(PathEvent.Failed(p, e.reason))
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

    /**
     * The peer address of every path the core had at the start of this drain or the last one (at most eight: four paths, and the ones
     * dropped since): a path the core drops before its event is drained (a failed preferred-address probe) still reports its own
     * address, not the connection's. Loop dispatcher only.
     */
    private val seenIds = IntArray(8)
    private val seenRemotes = arrayOfNulls<InetSocketAddress>(8)
    private var seen = 0

    /** Each path reports its own peer address ([PathRuntime.remote]); a handshake-time rebinding moves it. Loop dispatcher only. */
    private fun refreshPathRemotes() {
        val all = core.paths.all
        for (i in 0 until all.size) {
            val p = all[i]
            var j = 0
            while (j < seen && seenIds[j] != p.id.value) j++
            if (j == seen) {
                if (seen == seenIds.size) continue // cannot happen: at most four paths, and four dropped since the last drain
                seenIds[seen++] = p.id.value
            }
            seenRemotes[j] = p.remote
        }
        for (p in pathList) {
            val r = core.paths.byId(p.id)?.remote ?: continue
            if (r !== p.remote) p.remote = r
        }
    }

    /** Drops the remembered addresses of paths the core no longer has, once their events were drained. */
    private fun forgetDroppedRemotes() {
        var k = 0
        for (j in 0 until seen) {
            if (core.paths.byId(PathId(seenIds[j])) == null) continue
            seenIds[k] = seenIds[j]
            seenRemotes[k++] = seenRemotes[j]
        }
        for (j in k until seen) seenRemotes[j] = null
        seen = k
    }

    /** The peer address of path [id]: the core's, else the one last seen for it, else the connection's. */
    private fun lastRemote(id: PathId): InetSocketAddress {
        core.paths.byId(id)?.let { return it.remote }
        for (j in 0 until seen) if (seenIds[j] == id.value) return seenRemotes[j]!!
        return core.remoteAddress
    }

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

    /**
     * Applies queued send commands on the loop and flushes; one coroutine per connection, woken per burst. Started by the first
     * datagram: a connection that sends none never runs it, so its end cancels a coroutine that never suspended (no
     * CancellationException thrown through it; a handshake benchmark pays that per connection, docs/benchmarks.md).
     */
    private val datagramDrainer: Job =
        loop.scope.launch(start = CoroutineStart.LAZY) {
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
        datagramDrainer.start()
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
        datagramDrainer.start()
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
        refreshPathRemotes()
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
                    try {
                        loop.observer.handshakeCompleted(this)
                    } finally {
                        loop.onHandshakeCompleted(this) // a server connection reaches accept() whatever the callback did
                    }
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
                    // the core dropped every stream we opened (RFC 9001 section 4.6.2) and reuses their IDs: the wrappers made before
                    // fail and go; one made since (a stream opened while this event waited) names a live stream and stays
                    for (s in streams.values.filter { !it.current }) dropRejected(s)
                    loop.observer.zeroRtt(this, io.kuicksilver.quic.ZeroRttOutcome.Rejected)
                }

                is ConnectionEvent.StreamOpened -> {
                    accepted.trySend(
                        stream(e.id).also {
                            it.receivedEarly = core.streamReceivedEarly(e.id)
                            it.handOut.store(StreamRuntime.QUEUED)
                        },
                    )
                }

                is ConnectionEvent.StreamReadable -> {
                    wrapper(e.id)?.let {
                        it.updateReceivedAll()
                        it.signalReadable()
                    }
                }

                is ConnectionEvent.StreamWritable -> {
                    wrapper(e.id)?.ticker?.trySend(Unit) // the broadcast tick after each flush stays as the fallback
                }

                is ConnectionEvent.StreamReset -> {
                    val s = wrapper(e.id)
                    s?.peerReset(e.code, e.afterData)
                    if (s == null || !s.deferReset()) core.readStream(e.id, NO_BYTES, 0, 0)
                }

                // the reset is surfaced: acknowledge it in the core (ResetRecvd -> ResetRead) so the half retires, MAX_STREAMS credit returns and
                // StreamFinished follows; for a stream still waiting for acceptStream that happens when acceptStream hands it out
                is ConnectionEvent.StopSendingReceived -> {
                    wrapper(e.id)?.peerStopped(e.code)
                }

                is ConnectionEvent.StreamFinished -> {
                    wrapper(e.id)?.let {
                        streams.remove(e.id)
                        it.finished()
                    }
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
        if (core.receivedTokens != null) {
            val tokens = core.takeReceivedTokens()
            val store = tokenStore
            val key = tokenKey
            if (store != null && key != null) for (t in tokens) loop.storeToken(store, key, t)
        }
        forgetDroppedRemotes()
    }

    /** Client: where NEW_TOKEN tokens of this connection go (`QuicClientConfig.tokenStore`) and under which key; null: dropped. */
    internal var tokenStore: io.kuicksilver.quic.QuicTokenStore? = null
    internal var tokenKey: String? = null

    /**
     * Runs the (possibly application-supplied) verifier off the loop. A verifier that throws rejects the peer; a result that
     * arrives after the connection ended (handshake timeout, close) is dropped: the TLS session is already freed.
     */
    private suspend fun verify(e: ConnectionEvent.VerifyRequested) {
        val r =
            try {
                e.session.verifyPeer(e.chain)
            } catch (
                t: Throwable,
            ) {
                // our cancellation goes on; a CancellationException out of an application verifier rejects like any failure
                if (t is CancellationException) kotlinx.coroutines.currentCoroutineContext().ensureActive()
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

    /** The connection reached Closed and leaves the loop: everything, its path sockets included, is released. */
    internal fun finish() {
        retire(QuicException.ConnectionLost.Internal("connection finished", null))
    }

    /** [failed], and the path sockets are closed even when the core is still closing (the loop or the endpoint goes away). */
    internal fun retire(reason: QuicException.ConnectionLost) {
        failed(reason)
        releasePaths()
    }

    /**
     * The application side ends with [reason]. A connection still closing or draining keeps its path sockets and receivers until
     * [finish]: its CONNECTION_CLOSE goes out on the active path's socket, which after a migration is not the endpoint's, and is
     * repeated there for the peer's late packets (RFC 9000 section 10.2.1).
     */
    internal fun failed(reason: QuicException.ConnectionLost) {
        if (finished) return
        finished = true
        val handshakeDone = handshake.isCompleted && !handshake.isCancelled
        // the observer (application callbacks) runs last, once every waiter can see the end: whatever it does, `closed`,
        // the handshake and the streams are complete
        try {
            // before `closed` completes: whoever learns of the end from it sees which streams arrived whole
            for (s in streams.values) s.updateReceivedAll()
            closedDeferred.complete(reason)
            handshake.completeExceptionally(reason)
            accepted.close(reason)
            for (s in streams.values) s.connectionLost(reason)
            if (core.state == ConnectionState.Closed) releasePaths()
            datagramDrainer.cancel()
            sendQueue.close()
            datagramSignal.close()
            // every waiter (open, flush, keyUpdate, addPath, sendDatagram) wakes with the connection's own reason
            for (t in tickers) t.close(reason)
        } finally {
            loop.observer.closed(this, reason, handshakeDone)
        }
    }

    private fun releasePaths() {
        for (p in pathList) {
            p.receiver?.cancel()
            p.io?.let {
                it.close()
                loop.forgetDefunct(it) // a lost path socket is not remembered past its connection
            }
            if (!p.validation.isCompleted) p.validation.complete(false)
        }
    }

    /** The wrapper of the core's stream [id], unless the one in the map names a stream a rejected 0-RTT dropped. Loop only. */
    private fun wrapper(id: Long): StreamRuntime? = streams[id]?.takeIf { it.current }

    /** [s] names a stream a rejected 0-RTT dropped: it fails with EarlyDataRejected and leaves the map, if it is still there. Loop only. */
    internal fun dropRejected(s: StreamRuntime) {
        if (streams[s.id] === s) streams.remove(s.id)
        s.earlyDataRejected()
    }

    /**
     * The wrapper of the core's stream [id], made on first use. One in the map that names a stream a rejected 0-RTT dropped
     * (the runtime has not drained that event yet, and the core gave the freed ID to a new stream) is failed and replaced,
     * never handed out for the new stream.
     */
    private fun stream(
        id: Long,
        priority: StreamPriority = StreamPriority.Default,
    ): StreamRuntime {
        streams[id]?.let { if (it.live()) return it }
        val local = isLocal(id)
        return StreamRuntime(
            this,
            loop,
            id,
            recv = (id and 2L == 0L) || !local,
            send = (id and 2L == 0L) || local,
            initialPriority = priority,
            epoch = if (local) core.streams.zeroRttResets else -1,
        ).also { streams[id] = it }
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

    override suspend fun acceptStream(): QuicStream {
        val s = accepted.receive()
        // the application now holds the stream and its reset: the reset is consumed on the loop so the core counts the stream closed
        // (MAX_STREAMS credit). No suspension point follows the receive: a caller cancelled here would drop a stream already taken
        if (s.handOut.exchange(StreamRuntime.HANDED_OUT) == StreamRuntime.RESET_UNREAD) {
            loop.scope.launch {
                core.readStream(s.id, NO_BYTES, 0, 0)
                loop.flush(core)
            }
        }
        return s
    }

    /**
     * [s] left the accept queue but not for the application (its acceptStream caller was cancelled while being resumed) and the
     * closed queue cannot take it back: nothing will read or write it, so on the loop its reset, if one waits, is consumed and both halves are given up as an application would
     * (STOP_SENDING, RESET_STREAM with the default code), and the stream closes and returns its credit.
     */
    private fun abandonUndelivered(s: StreamRuntime) {
        loop.scope.launch {
            if (s.handOut.exchange(StreamRuntime.HANDED_OUT) == StreamRuntime.RESET_UNREAD) core.readStream(s.id, NO_BYTES, 0, 0)
            core.stopSending(s.id, defaultCode())
            core.resetStream(s.id, defaultCode())
            loop.flush(core)
        }
    }

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
