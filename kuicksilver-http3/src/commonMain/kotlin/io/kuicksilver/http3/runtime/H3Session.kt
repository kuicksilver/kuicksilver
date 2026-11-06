// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3PeerSettings
import io.kuicksilver.http3.Http3Role
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.message.GlitchLimiter
import io.kuicksilver.http3.qpack.QpackError
import io.kuicksilver.http3.webtransport.WtSettings
import io.kuicksilver.http3.webtransport.WtStreamRouter
import io.kuicksilver.http3.webtransport.WtVersion
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicPath
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.activePath
import io.kuicksilver.quic.awaitFinished
import io.kuicksilver.quic.receivedAll
import io.kuicksilver.quic.runtime.QuicStreamLimits
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlin.concurrent.atomics.AtomicLong
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * The runtime of one HTTP/3 connection (RFC 9114 section 6): our control and QPACK streams, the peer's unidirectional
 * streams (read greedily, RFC 9308 section 4.4), SETTINGS, and connection errors. Every coroutine runs on one
 * single-threaded dispatcher, so the session's state needs no locks; the mutexes only keep writes to one stream whole.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
internal class H3Session(
    val quic: QuicConnection,
    val role: Http3Role,
    val settings: Http3Settings,
) {
    val isServer: Boolean get() = role == Http3Role.Server
    val dispatcher = Dispatchers.Default.limitedParallelism(1)
    internal val job = SupervisorJob()
    val scope = CoroutineScope(job + dispatcher + CoroutineName("http3"))

    /** Where [launchDrainer] readers run: outside [scope], so one started after the connection ended still runs. */
    internal val afterEnd = CoroutineScope(SupervisorJob() + dispatcher + CoroutineName("http3-drain"))

    /** How [DRAIN_GRACE] is measured; a test replaces it to end the grace without real time passing. */
    internal var drainTimer: suspend (Duration) -> Unit = { delay(it) }

    /** Test hook: runs before each [launchDrainer] reader, so a test can hold one past the end of the connection. */
    internal var beforeDrainerForTest: (suspend () -> Unit)? = null

    /** Coroutines reading what the peer sent, which may finish it when the connection is lost ([drains]). */
    internal val drainers = kotlin.concurrent.atomics.AtomicReference<List<Drainer>>(emptyList())

    /** A [drains] reader, and the stream whose message it reads, if any. */
    internal class Drainer(
        val job: Job,
        val stream: QuicStream?,
    )

    /**
     * The peer's QPACK encoder stream is being read. Once the connection is gone and this reader too, no insert can arrive
     * any more: a field section still waiting for one never decodes ([noMoreInserts]). Session dispatcher only.
     */
    internal var peerEncoderReading = false

    /** No dynamic-table insert can arrive any more: the connection is gone, and with it the reader of the peer's encoder stream. */
    fun noMoreInserts(): Boolean = closed.isCompleted && !peerEncoderReading

    val peerSettings = MutableStateFlow<Http3PeerSettings?>(null)
    internal val peerSettingsArrived = CompletableDeferred<Http3PeerSettings>()
    val datagrams = DatagramDemux(this)

    /** WebTransport streams to their sessions (only used with [Http3Settings.webTransport]). */
    val wt = WtStreamRouter(this)

    /**
     * Server: the request stream of the WebTransport CONNECT handed to the application and not yet over; while it is set
     * another one is refused with H3_REQUEST_REJECTED (one session per connection, draft-ietf-webtrans-http3-16 section
     * 5.1). Session dispatcher only.
     */
    var wtSessionStream: Long? = null
        set(v) {
            field = v
            wtIdle.value = v == null
        }

    /** Client: a WebTransport session is being opened or is open on this connection (one at a time). Dispatcher only. */
    var wtClientBusy = false
        set(v) {
            field = v
            wtIdle.value = !v
        }

    /** No WebTransport session holds this connection's slot (a test hook). */
    val wtIdle = MutableStateFlow(true)

    /**
     * How long each step of opening or accepting a WebTransport session may wait for the peer: its SETTINGS, and (client)
     * the answer to the CONNECT. Ten seconds.
     */
    val wtDeadline: Duration = WT_DEADLINE

    /** How a WebTransport wait measures [wtDeadline]; a test replaces it to end the wait without real time passing. */
    var wtTimer: suspend (Duration) -> Unit = { delay(it) }

    /**
     * [block], or null when [wtDeadline] (measured by [wtTimer]) passed first; [block] is then cancelled, and this returns
     * once its cancellation finished (a CONNECT in flight is reset by it).
     */
    suspend fun <T : Any> withinWtDeadline(block: suspend () -> T): T? =
        coroutineScope {
            val work = async { block() }
            val timer = launch { wtTimer(wtDeadline) }
            select {
                work.onAwait {
                    timer.cancel()
                    it
                }
                timer.onJoin {
                    work.cancel()
                    null
                }
            }
        }

    val goAwayReceived = MutableStateFlow<Long?>(null)
    val closed = CompletableDeferred<Throwable>()
    val requests = Channel<ServerRequestImpl>(Channel.UNLIMITED)

    /** Test hook: the client sends unsafe requests in 0-RTT too (to exercise the server's RFC 8470 gate). */
    internal var testSendUnsafeEarly = false

    /**
     * Test hook: runs on each request stream before its first frame is read, so a test can let a reset arrive first (a
     * request stream reset before its HEADERS are read surfaces no request).
     */
    internal var beforeRequestHeadersForTest: (suspend (QuicStream) -> Unit)? = null

    /** Requests repeated after a 425 Too Early (RFC 8470 section 5.2). */
    internal var early425Retries = 0

    /** PRIORITY_UPDATE frames for request streams the peer sent (a test hook; dispatcher only). */
    internal var priorityUpdatesForTest = 0

    /** Early requests sent again after the server rejected 0-RTT (RFC 9001 section 4.6.2). */
    internal var earlyRejectedRetries = 0

    /** Test hook: requests that came in 0-RTT and waited for the handshake (RFC 8470 gate). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val earlyHeldForHandshake = kotlin.concurrent.atomics.AtomicInt(0)

    /** The path the connection sends on now (`remoteAddress` follows migration, RFC 9000 section 9). */
    var currentPath: QuicPath = quic.paths.first()
        private set

    /** Our control and QPACK streams, once open, typed and with SETTINGS sent; null until then and after a rejected 0-RTT dropped them. */
    internal class Critical(
        val control: QuicStream,
        val encoder: QuicStream,
        val decoder: QuicStream,
    )

    internal var critical: Critical? = null

    /**
     * Client: how often our critical streams were given up because the server rejected the 0-RTT that carried them (RFC 9001
     * section 4.6.2). What was made for the streams of an older generation is not written on newer ones. Dispatcher only.
     */
    internal var criticalGen = 0

    /** Client: the rejected 0-RTT was noted ([noteRejectedZeroRtt]). Dispatcher only. */
    internal var zeroRttRejectionNoted = false

    /** [zeroRttRejectionNoted] (a test hook; dispatcher only). */
    internal val zeroRttRejectionNotedForTest: Boolean get() = zeroRttRejectionNoted

    /** The streams the running [openCriticalStreams] attempt opened so far (the set of [critical] once it is done). Dispatcher only. */
    internal var attemptStreams: List<QuicStream> = emptyList()

    /** Streams of [attemptStreams] whose type went to the transport: never reset, a typed critical stream is for good. Dispatcher only. */
    internal val typedStreams = ArrayList<QuicStream>(3)

    /**
     * Client: control frames written on the first control stream before the handshake told whether the server took the 0-RTT
     * it rode, with whether each is still wanted. A rejection drops that stream with them; the new control stream carries
     * them again, after SETTINGS. Null once settled. Dispatcher only.
     */
    internal var earlyControl: ArrayList<Pair<ByteArray, () -> Boolean>>? = if (role == Http3Role.Client) ArrayList() else null

    /** Test hook: fail when the critical-stream bookkeeping runs anywhere but on [dispatcher] (review 2026-10-28 N3). */
    @kotlin.concurrent.Volatile
    internal var assertOnDispatcherForTest = false

    /** Throws under [assertOnDispatcherForTest] when the caller is not on [dispatcher]. */
    internal suspend fun checkOnDispatcher() {
        if (assertOnDispatcherForTest) {
            check(currentCoroutineContext()[kotlin.coroutines.ContinuationInterceptor] === dispatcher) { "off the session's dispatcher" }
        }
    }

    /** Writes on our critical streams that a rejected 0-RTT failed (a test hook). */
    internal val criticalWriteFailuresForTest = kotlin.concurrent.atomics.AtomicInt(0)

    /** Test hook: runs on the dispatcher at the steps of each [openCriticalStreams] attempt ([AttemptStep]), with the attempt's generation. */
    internal var criticalAttemptHookForTest: (suspend (AttemptStep, Int) -> Unit)? = null

    /** Where an [openCriticalStreams] attempt is ([criticalAttemptHookForTest]). */
    internal enum class AttemptStep { Started, Opened, ControlWritten }

    internal val controlLock = Mutex()
    internal val encoderLock = Mutex()
    internal val decoderLock = Mutex()
    val qpack =
        QpackRuntime(
            settings,
            { b -> writeCritical(encoderLock, { it.encoder }, b) },
            { b -> queueDecoderBytes(b) },
        )

    /**
     * Decoder-stream bytes waiting for [decoderWriter], each with the critical-stream generation it was made for. The decoder
     * stream's output never makes its caller wait: a peer that grants that stream no credit would otherwise block every
     * QPACK cancellation and acknowledgment, NonCancellable ones included, so requests could no longer be cancelled (review
     * S1). What the peer does not take is bounded by [decoderQueueLimit].
     */
    private val decoderQueue = Channel<Pair<Int, ByteArray>>(Channel.UNLIMITED)
    private val decoderQueued = AtomicLong(0)

    /**
     * Decoder-stream bytes queued and not written yet above which the connection ends with H3_EXCESSIVE_LOAD: a decoder that
     * cannot hand its instructions over is a peer not reading its encoder's feedback (RFC 9204 section 7.3 asks for bounds on
     * what a peer can make us buffer). Tests lower it.
     */
    var decoderQueueLimit: Long = DECODER_QUEUE_LIMIT

    private fun queueDecoderBytes(b: ByteArray) {
        if (decoderQueued.addAndFetch(b.size.toLong()) > decoderQueueLimit) {
            scope.launch { fail(Http3ErrorCode.EXCESSIVE_LOAD, "the peer does not take our decoder stream's instructions") }
            return
        }
        decoderQueue.trySend(criticalGen to b)
    }

    /** Writes the queued decoder-stream bytes in order, each on the decoder stream of the generation it was made for. */
    private suspend fun decoderWriter() {
        for ((gen, b) in decoderQueue) {
            try {
                writeCritical(decoderLock, { it.decoder }, b, madeFor = gen)
            } finally {
                decoderQueued.addAndFetch(-b.size.toLong())
            }
        }
    }

    internal val peerUni = HashSet<Long>() // stream types seen: one control, one encoder, one decoder

    /** The peer's critical streams whose type was read (a test hook). */
    val criticalStreamsSeen = MutableStateFlow(0)

    /** The peer's unidirectional streams dropped unread: ended or reset before their type, or of an unknown type (a test hook). */
    val discardedUniStreams = MutableStateFlow(0)
    private val glitch = if (settings.glitchProtection) GlitchLimiter() else null
    private val clock = TimeSource.Monotonic.markNow()

    /** The glitch bucket's clock in nanoseconds (it refills 33 tokens a second); a test freezes it so the bucket cannot refill. */
    @kotlin.concurrent.Volatile
    internal var glitchClock: () -> Long = { clock.elapsedNow().inWholeNanoseconds }

    // GOAWAY (RFC 9114 section 5.2)
    internal var goAwayPhase = 0 // 0 none, 1 first (2^62-4) sent, 2 final sent

    /** Server: requests with ids from here on are rejected; client: 0 once we sent ours. */
    var goAwaySentId: Long? = null
        internal set
    var maxRequestId = -1L // server: highest client stream id seen

    // server: accepted requests whose response has not ended (and request streams whose HEADERS are still being read)
    private val activeRequestCount = MutableStateFlow(0)
    internal var activeRequests: Int
        get() = activeRequestCount.value
        set(v) {
            activeRequestCount.value = v
        }

    /** Test hook: [activeRequests] as a flow, so a test can wait for every request stream to be accounted for. */
    internal val activeRequestsForTest: StateFlow<Int> get() = activeRequestCount

    /** Server: how long a request stream may take to complete its HEADERS once the final GOAWAY went out; internal for tests. */
    var headerDeadlineAfterGoAway: Duration = HEADER_DEADLINE_AFTER_GOAWAY

    /**
     * Server, after the final GOAWAY: how long an idle connection whose answered request streams are all finished at the
     * transport level waits for the client to close it (a Kuicksilver client does once its responses are read) before the
     * server closes it itself. Settable by tests.
     */
    var goAwayCloseFallback: Duration = GOAWAY_CLOSE_FALLBACK

    /** Server: answered request streams not yet finished at the transport level (response unacknowledged). Session dispatcher only. */
    internal var settling = 0

    /** Client: exchanges whose request or response is still moving; idle after a GOAWAY, the client closes. Dispatcher only. */
    internal var openExchanges = 0

    /** Server: request streams still reading their HEADERS, with the coroutine reading them. */
    val pendingHeaders = HashMap<Long, Pair<QuicStream, Job>>()

    /** Server: the header deadline after GOAWAY passed; a request stream that still has no HEADERS is rejected. */
    var headerDeadlinePassed = false
        internal set
    val rejectedByGoAway = HashSet<Long>() // client: in-flight requests the peer's GOAWAY did not cover
    val clientStreams = HashMap<Long, QuicStream>() // client: requests waiting for their response

    // RFC 9218 (server)
    val activeServerRequests = HashMap<Long, ServerRequestImpl>()
    internal val earlyPriority = LinkedHashMap<Long, StreamPriority>() // PRIORITY_UPDATE for streams not open yet

    /** Server: the highest client bidirectional stream taken from the transport; the transport hands them out in id order. */
    internal var acceptedBidiUpTo = -1L

    /** Server: client bidirectional streams taken from the transport whose handler has not ended (HEADERS may still be on the way). */
    internal val handledBidi = HashSet<Long>()

    /** Server: [handledBidi] streams whose HEADERS were read (or that are no request): they never become a session now. */
    private val settledBidi = HashSet<Long>()

    /**
     * Client: requests other than CONNECT, whose streams have no datagram semantics (RFC 9297 section 2), until their
     * exchange settled. Session dispatcher only.
     */
    val clientRequestsWithoutDatagrams = HashMap<Long, QuicStream>()

    /** Server: the client's last MAX_PUSH_ID, -1 before the first (we never push; kept to catch a decrease). Dispatcher only. */
    var peerMaxPushId = -1L
        internal set

    /** HEADERS frames above this are refused unread; QPACK output is never much larger than the decoded section it carries. */
    val maxHeadersFrame: Long get() = 2 * settings.maxFieldSectionSize

    /** Bytes of HEADERS payloads being read on request streams right now (a test hook; session dispatcher only). */
    var bufferedHeaderBytes = 0L

    /** Completes once our control and QPACK streams are open and typed and our SETTINGS went out; a new one after a rejected 0-RTT. */
    internal var criticalStreams = CompletableDeferred<Unit>()

    /**
     * Starts the session. A coroutine of the session opens our control and QPACK streams: opening a stream waits for the
     * peer's stream credit (RFC 9000 section 4.6), and a peer whose transport parameters allow fewer than the three
     * unidirectional streams HTTP/3 needs (RFC 9114 section 6.2: they "MUST allow the peer to create at least three") would
     * hold the caller forever. Without them after [criticalStreamsDeadline] the connection closes with
     * H3_GENERAL_PROTOCOL_ERROR. A server returns at once, so an accept loop never waits on one peer; a client returns once
     * its SETTINGS went out and throws the connection's error when the streams could not be opened. A client in 0-RTT
     * opens them and sends SETTINGS at once too, as RFC 9114 section 7.2.4.2 requires ("settings MUST be sent as soon as the
     * transport is ready to send data"); when the server rejects the 0-RTT, which resets every stream the client opened
     * (RFC 9001 section 4.6.2), it opens them again and sends SETTINGS once more ([criticalStreamsLoop]). A
     * client that received GOAWAY first (a server stopping right after the handshake) returns too: it closed itself, idle, as
     * RFC 9114 section 5.2 lets it, and a request then fails with the retry-safe [Http3Exception.RequestNotProcessed]; its
     * own H3_NO_ERROR close, or the server's that came first, is no failure of the connection to report. Every other error
     * still fails the start.
     */
    suspend fun start(criticalStreamsDeadline: Duration = CRITICAL_STREAMS_DEADLINE) {
        scope.launch {
            val e = quic.closed.await()
            onTransportClosed(e)
        }
        scope.launch { guarded { criticalStreamsLoop(criticalStreamsDeadline) } }
        scope.launch { guarded { decoderWriter() } }
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            quic.pathEvents.collect { if (it is PathEvent.Changed) currentPath = it.new }
        }
        // each path reports its own peer address: a change before the collector started (a NAT rebinding right after the handshake)
        // must not leave the session on the path the peer left
        quic.activePath?.let { currentPath = it }
        scope.launch { acceptLoop() }
        datagrams.start()
        if (isServer) return
        try {
            withContext(dispatcher) { awaitCriticalStreams() }
        } catch (e: Http3Exception) {
            startEndedForTest?.invoke(this)
            // a peer's H3_NO_ERROR close that arrived with its GOAWAY can be handled before the control reader parsed that
            // GOAWAY (review 2026-10-28 quic-h3.md R3): the readers that drain the peer's streams finish what arrived, at most
            // DRAIN_GRACE after the end, and the session's job ends then; only after that is the GOAWAY known to be absent
            if (!isGracefulEndAfterGoAway(e) && e is Http3Exception.Protocol && e.h3Code == Http3ErrorCode.NO_ERROR) job.join()
            if (!isGracefulEndAfterGoAway(e)) throw e
        }
    }

    /**
     * [e] is a graceful end after the peer's GOAWAY (RFC 9114 section 5.2): our own H3_NO_ERROR idle close
     * ([closeIfIdleAfterGoAway]), or the peer's H3_NO_ERROR close, which it "MAY initiate" at once and which can come
     * before ours. Any other end (a protocol error after the GOAWAY, an error close of either side) is a failure to report,
     * whether or not a GOAWAY came first.
     */
    private fun isGracefulEndAfterGoAway(e: Http3Exception): Boolean =
        goAwayReceived.value != null &&
            e is Http3Exception.Protocol &&
            e.h3Code == Http3ErrorCode.NO_ERROR

    /** The peer's SETTINGS; waits for them, or throws the connection's error if it closes first. */
    suspend fun awaitPeerSettings(): Http3PeerSettings =
        select {
            peerSettingsArrived.onAwait { it }
            closed.onAwait { throw it }
        }

    /** The highest WebTransport draft the peer's SETTINGS announce; null before they arrived or when they announce none. */
    fun peerWtVersion(): WtVersion? = peerWtVersion

    internal var peerWtVersion: WtVersion? = null

    internal fun ourSettings(): List<Pair<Long, Long>> =
        buildList {
            if (settings.qpackMaxTableCapacity > 0) add(SettingsId.QPACK_MAX_TABLE_CAPACITY to settings.qpackMaxTableCapacity)
            if (settings.qpackBlockedStreams > 0) add(SettingsId.QPACK_BLOCKED_STREAMS to settings.qpackBlockedStreams)
            add(SettingsId.MAX_FIELD_SECTION_SIZE to settings.maxFieldSectionSize)
            if (settings.enableConnectProtocol) add(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L)
            add(SettingsId.H3_DATAGRAM to if (settings.h3Datagram) 1L else 0L)
            if (settings.webTransport) addAll(WtSettings.ours(isServer))
            if (settings.grease) add(FrameType.grease(Random.nextLong(0, 1000)) to Random.nextLong(0, 1L shl 30))
        }

    /** Runs [block], turning protocol errors into connection errors; transport loss is reported by the closed handler. */
    suspend fun guarded(block: suspend () -> Unit) {
        try {
            block()
        } catch (
            e: CancellationException,
        ) {
            throw e
        } catch (
            e: H3ProtocolError,
        ) {
            fail(e.code, e.message ?: "")
        } catch (
            e: QpackError,
        ) {
            fail(e.code, e.message ?: "")
        } catch (e: QuicException.ConnectionLost) {
        } catch (e: Throwable) {
            // our transport is gone and ktor-io wrapped its cause (a ClosedWriteChannelException after a peer close, an idle
            // timeout, a stateless reset): its close reports the end, never an H3_INTERNAL_ERROR of ours that won the race
            // to complete [closed] (onTransportClosed runs in a coroutine of its own). A ConnectionLost of another
            // connection (a handler relaying elsewhere) is still a failure here.
            if (transportCause(e) is QuicException.ConnectionLost && quic.closed.isCompleted) return
            if (!closed.isCompleted) {
                fail(
                    Http3ErrorCode.INTERNAL_ERROR,
                    e.message ?: e::class.simpleName ?: "internal error",
                )
            }
        }
    }

    /** What [acceptNext] took; acceptLoop's coroutine only. */
    private var nextAccepted: QuicStream? = null

    /**
     * Takes the next peer stream into [nextAccepted] and returns Unit. Not `val st = quic.acceptStream()` in [acceptLoop]: a
     * suspending call that waited hands its result to the caller's coroutine frame, which keeps it in its result slot until
     * the frame is resumed again. The accept loop's frame then held the connection's last request stream (its input buffer
     * and an 8 KiB kotlinx-io segment, about 10 KB per idle connection) for as long as no new stream came, reachable from
     * the accept queue's waiter (docs/benchmarks.md, "Memory"). This frame ends with the call; the loop's is resumed with Unit.
     */
    private suspend fun acceptNext() {
        nextAccepted = quic.acceptStream()
    }

    private suspend fun acceptLoop() {
        while (true) {
            val st =
                try {
                    acceptNext()
                    nextAccepted!!.also { nextAccepted = null }
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    return
                }
            // nothing of the server is read before a rejected 0-RTT is noted: QPACK must have forgotten the early streams first
            noteRejectedZeroRttHere()
            // the peer's streams are read to their end even when the connection is lost (drains)
            if (st.id and 2L != 0L) {
                drains(scope.launch { guarded { readUni(st) } })
            } else if (isServer) {
                acceptedBidiUpTo = st.id
                handledBidi += st.id
                drains(
                    scope.launch {
                        try {
                            guarded { handleRequestStream(this@H3Session, st) }
                        } finally {
                            handledBidi -= st.id
                            settledBidi -= st.id
                            earlyPriority.remove(st.id) // a stream that never became a request (aborted, WebTransport) keeps no slot
                            datagrams.dropPending(st.id)
                        }
                    },
                    st,
                )
            } else if (settings.webTransport) {
                scope.launch { guarded { serverBidi(st) } }
            } else {
                fail(Http3ErrorCode.STREAM_CREATION_ERROR, "server-initiated bidirectional stream ${st.id}")
                return
            }
        }
    }

    /**
     * Client with WebTransport: a server-initiated bidirectional stream is a WebTransport stream, which starts with the
     * `WT_STREAM` signal (draft-ietf-webtrans-http3-16 section 4.3); anything else is H3_STREAM_CREATION_ERROR as without
     * WebTransport (RFC 9114 section 6.1). One that ends or is reset before its first bytes is dropped.
     */
    private suspend fun serverBidi(st: QuicStream) {
        val first =
            try {
                st.input.readVarIntOrNull()
            } catch (_: IncompleteFrame) {
                null
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                if (transportCause(e) !is QuicException.StreamError) throw e
                null
            } ?: run {
                glitch("server-initiated bidirectional stream ended before its first bytes")
                return
            }
        if (first != FrameType.WT_STREAM) {
            throw H3ProtocolError(Http3ErrorCode.STREAM_CREATION_ERROR, "server-initiated bidirectional stream ${st.id}")
        }
        wt.onBidi(st)
    }

    fun takeEarlyPriority(id: Long): StreamPriority? = earlyPriority.remove(id)

    /**
     * Server: client bidirectional stream [id] may still become a request: the transport has not handed it out yet (and
     * it is within the limit we granted), or its handler is still reading its HEADERS. Session dispatcher only.
     */
    fun requestMayStillOpen(id: Long): Boolean {
        if (id in handledBidi) return id !in settledBidi
        if (id <= acceptedBidiUpTo) return false
        return QuicStreamLimits.peerBidiStreamsGranted(quic)?.let { id / 4 < it } ?: true
    }

    /**
     * Server: client bidirectional stream [id] exists (the transport handed it out) and its HEADERS are still on the way: a
     * datagram for it may wait as long as an early WebTransport stream does (see [DatagramDemux]). Session dispatcher only.
     */
    fun requestOpenWithoutHeaders(id: Long): Boolean = id in handledBidi && id !in settledBidi

    /** Server: stream [id] read its HEADERS, or turned out to be no request (a WebTransport stream): see [requestMayStillOpen]. */
    fun bidiSettled(id: Long) {
        settledBidi += id
    }

    /**
     * RFC 9297 section 2: "If an HTTP Datagram is received and it is associated with a request that has no known semantics
     * for HTTP Datagrams, the receiver MUST terminate the request. If HTTP/3 is in use, the request stream MUST be aborted
     * with H3_DATAGRAM_ERROR". Only an Extended CONNECT whose protocol is not `websocket` has them ([hasDatagramSemantics]):
     * GET and POST are the RFC's examples of requests without, and a classic CONNECT and RFC 9220 define none. Section 2.1
     * comes first once the request's direction is over ("MUST be silently dropped"): only a stream still receiving is
     * aborted. A direction is over once every byte and the FIN arrived (RFC 9000 "Data Recvd", [receivedAll]), also while
     * the application has not read them yet, so a message that came whole is never aborted by a stray datagram (review
     * 2026-10-28 H3R-6). Returns whether [id] was such a request.
     */
    suspend fun abortRequestWithoutDatagrams(id: Long): Boolean {
        if (isServer) {
            val req = activeServerRequests[id] ?: return false
            if (hasDatagramSemantics(req.method, req.protocol) || receiveOver(req.stream)) return false
            abort(req.stream, Http3ErrorCode.DATAGRAM_ERROR)
            req.done()
        } else {
            val st = clientRequestsWithoutDatagrams[id] ?: return false
            if (receiveOver(st)) return false
            abort(st, Http3ErrorCode.DATAGRAM_ERROR)
        }
        return true
    }

    /** Whether the peer's direction of [st] is over: all of it arrived, or it was read to its end or failed. */
    private fun receiveOver(st: QuicStream): Boolean = st.receivedAll || st.input.isClosedForRead

    /**
     * Client bidirectional stream [id] lies beyond the stream limit: the one we granted on a server, the one the server
     * granted us on a client. No request can ever use it. False when the transport does not say.
     */
    fun beyondBidiStreamLimit(id: Long): Boolean {
        val limit =
            if (isServer) QuicStreamLimits.peerBidiStreamsGranted(quic) else QuicStreamLimits.localBidiStreamsAllowed(quic)
        return limit != null && id / 4 >= limit
    }

    /** Spends a glitch token; an empty bucket is a connection error H3_EXCESSIVE_LOAD (RFC 9114 section 8.1). */
    fun glitch(what: String) {
        val g =
            glitch ?: return
        if (!g.spend(glitchClock())) {
            throw H3ProtocolError(Http3ErrorCode.EXCESSIVE_LOAD, "too much useless work: $what")
        }
    }

    /** Runs on the session dispatcher right after a request's exchange was set up, before `request` returns (test hook). */
    internal var afterRequestForTest: (() -> Unit)? = null

    /** The context [goAway] ran in (test hook). */
    internal var goAwayContextForTest: ((kotlin.coroutines.CoroutineContext) -> Unit)? = null

    fun requestStarted() {
        activeRequests++
    }

    fun requestDone() {
        activeRequests--
        if (goAwayPhase == 2) scope.launch { closeIfIdle() }
    }

    /**
     * Server: [st]'s response was handed to QUIC; until the stream is finished at the transport level (everything
     * acknowledged) the GOAWAY idle close waits for it. A response handed over is not yet received: closing 200 ms after
     * it cut responses still in flight or held back by flow control (the client then lost their bodies).
     */
    fun responseHandedOver(st: QuicStream) {
        settling++
        scope.launch {
            try {
                @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                st.awaitFinished()
            } finally {
                settling--
                if (goAwayPhase == 2) scope.launch { closeIfIdle() }
            }
        }
    }

    /** Client: a request stream was opened; [exchangeEnded] follows once its request and response are done. */
    fun exchangeOpened() {
        openExchanges++
    }

    fun exchangeEnded() {
        openExchanges--
        closeIfIdleAfterGoAway()
    }

    /**
     * Sends a frame on our control stream. One that a rejected 0-RTT dropped with the stream goes again on the new control
     * stream while [again] says it is still wanted.
     */
    suspend fun sendControl(
        type: Long,
        payload: ByteArray,
        again: () -> Boolean = { true },
    ) {
        writeCritical(controlLock, { it.control }, FrameHeaders.frame(type, payload), again)
    }

    /** What a stream operation throws once the connection is gone. */
    fun connectionError(): Throwable = if (closed.isCompleted) closed.getCompleted() else IllegalStateException("connection open")

    /** Maps a transport failure seen on a stream to the exception the application gets. */
    fun map(e: Throwable): Throwable {
        if (e is Http3Exception) return e
        val q = transportCause(e) ?: return e // ktor-io wraps the cause of a failed write in ClosedWriteChannelException
        return if (q is QuicException.ConnectionLost && closed.isCompleted) closed.getCompleted() else Http3Exception.fromQuic(q)
    }

    init {
        createdForTest?.invoke(this) // last: every property above is set
    }

    companion object {
        /**
         * Test hook: sees every session as it is made, before it starts (to install the per-session hooks). It is global, so
         * it is not safe for tests that run in parallel in one process (none do: each module's tests run one after another);
         * a test sets it right before the connection it is for and takes the first matching session only.
         */
        @kotlin.concurrent.Volatile
        internal var createdForTest: ((H3Session) -> Unit)? = null

        /** Test hook: runs when the start's wait ended with an error, before it decides whether that error fails the start. */
        @kotlin.concurrent.Volatile
        internal var startEndedForTest: ((H3Session) -> Unit)? = null

        /** Test hook: runs before a control frame of [type] the peer sent is handled (global: a test filters on the session). */
        @kotlin.concurrent.Volatile
        internal var beforeControlFrameForTest: (suspend (H3Session, type: Long) -> Unit)? = null

        /** Test hook: runs before a client's idle close after GOAWAY, so a test can let the peer's close win the race. */
        @kotlin.concurrent.Volatile
        internal var beforeIdleCloseForTest: (suspend (H3Session) -> Unit)? = null

        /** A client that started a request before GOAWAY gets this long to finish its HEADERS (no RFC value; see docs/guide/http3.md). */
        val HEADER_DEADLINE_AFTER_GOAWAY: Duration = 10.seconds
        val GOAWAY_CLOSE_FALLBACK: Duration = 3.seconds

        /**
         * How long a new connection may take to open our control and QPACK streams. A peer that follows RFC 9114 section 6.2
         * allows them in its transport parameters, so they open at once; only a peer that does not is held up here.
         */
        val CRITICAL_STREAMS_DEADLINE: Duration = 3.seconds

        /** How long readers may go on finishing what a peer sent once its connection is lost ([drains]). */
        val DRAIN_GRACE: Duration = 1.seconds

        /** See [decoderQueueLimit]. */
        const val DECODER_QUEUE_LIMIT: Long = 64L * 1024

        internal const val DRAINERS_PRUNE_MIN = 64

        /** Control and QPACK streams: sent before every request stream, whatever urgency a peer asks for. */
        val CRITICAL = StreamPriority.Critical

        /** A peer that speaks HTTP/3 sends SETTINGS first thing (RFC 9114 section 6.2.1): ten seconds is plenty. */
        val WT_DEADLINE: Duration = 10.seconds
        const val MAX_PRIORITY_UPDATE = 256

        fun transportCause(e: Throwable): QuicException? =
            generateSequence(e) {
                it.cause
            }.take(8).firstOrNull { it is QuicException } as QuicException?
    }
}
