// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3PeerSettings
import io.kuicksilver.http3.Http3Role
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameAction
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameRules
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.frame.SettingsCodec
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.message.GlitchLimiter
import io.kuicksilver.http3.message.PriorityField
import io.kuicksilver.http3.qpack.QpackError
import io.kuicksilver.http3.qpack.entrySize
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicPath
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
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
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * The runtime of one HTTP/3 connection (RFC 9114 section 6): our control and QPACK streams, the peer's unidirectional
 * streams (read greedily, RFC 9308 section 4.4), SETTINGS, and connection errors. Every coroutine runs on one
 * single-threaded dispatcher, so the session's state needs no locks; the mutexes only keep writes to one stream whole.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
internal class H3Session(
    val quic: QuicConnection,
    val role: Http3Role,
    val settings: Http3Settings,
) {
    val isServer: Boolean get() = role == Http3Role.Server
    val dispatcher = Dispatchers.Default.limitedParallelism(1)
    private val job = SupervisorJob()
    val scope = CoroutineScope(job + dispatcher + CoroutineName("http3"))

    /** Where a [launchDrainer] reader started after the connection ended runs. */
    private val afterEnd = CoroutineScope(SupervisorJob() + dispatcher + CoroutineName("http3-drain"))

    /** How [DRAIN_GRACE] is measured; a test replaces it to end the grace without real time passing. */
    internal var drainTimer: suspend (Duration) -> Unit = { delay(it) }

    /** Test hook: runs before each [launchDrainer] reader, so a test can hold one past the end of the connection. */
    internal var beforeDrainerForTest: (suspend () -> Unit)? = null

    /** Coroutines reading what the peer sent, which may finish it when the connection is lost ([drains]); dispatcher only. */
    private val drainers = ArrayList<Drainer>()
    private var drainersPruneAt = DRAINERS_PRUNE_MIN

    /** A [drains] reader, and the stream whose message it reads, if any. */
    private class Drainer(
        val job: Job,
        val stream: QuicStream?,
    )

    /**
     * The peer's QPACK encoder stream is being read. Once the connection is gone and this reader too, no insert can arrive
     * any more: a field section still waiting for one never decodes ([noMoreInserts]). Session dispatcher only.
     */
    private var peerEncoderReading = false

    /** No dynamic-table insert can arrive any more: the connection is gone, and with it the reader of the peer's encoder stream. */
    fun noMoreInserts(): Boolean = closed.isCompleted && !peerEncoderReading

    val peerSettings = MutableStateFlow<Http3PeerSettings?>(null)
    private val peerSettingsArrived = CompletableDeferred<Http3PeerSettings>()
    val datagrams = DatagramDemux(this)
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

    /** Test hook: requests that came in 0-RTT and waited for the handshake (RFC 8470 gate). */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val earlyHeldForHandshake = kotlin.concurrent.atomics.AtomicInt(0)

    /** The path the connection sends on now (`remoteAddress` follows migration, RFC 9000 section 9). */
    var currentPath: QuicPath = quic.paths.first()
        private set

    private lateinit var control: QuicStream
    private lateinit var encoderStream: QuicStream
    private lateinit var decoderStream: QuicStream
    private val controlLock = Mutex()
    private val encoderLock = Mutex()
    private val decoderLock = Mutex()
    val qpack =
        QpackRuntime(
            settings,
            { b ->
                awaitCriticalStreams()
                encoderLock.withLock {
                    encoderStream.output.writeFully(b)
                    encoderStream.output.flush()
                }
            },
            { b ->
                awaitCriticalStreams()
                decoderLock.withLock {
                    decoderStream.output.writeFully(b)
                    decoderStream.output.flush()
                }
            },
        )
    private val peerUni = HashSet<Long>() // stream types seen: one control, one encoder, one decoder

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
    private var goAwayPhase = 0 // 0 none, 1 first (2^62-4) sent, 2 final sent

    /** Server: requests with ids from here on are rejected; client: 0 once we sent ours. */
    var goAwaySentId: Long? = null
        private set
    var maxRequestId = -1L // server: highest client stream id seen

    // server: accepted requests whose response has not ended (and request streams whose HEADERS are still being read)
    private val activeRequestCount = MutableStateFlow(0)
    private var activeRequests: Int
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
    private var settling = 0

    /** Client: exchanges whose request or response is still moving; idle after a GOAWAY, the client closes. Dispatcher only. */
    private var openExchanges = 0

    /** Server: request streams still reading their HEADERS, with the coroutine reading them. */
    val pendingHeaders = HashMap<Long, Pair<QuicStream, Job>>()

    /** Server: the header deadline after GOAWAY passed; a request stream that still has no HEADERS is rejected. */
    var headerDeadlinePassed = false
        private set
    val rejectedByGoAway = HashSet<Long>() // client: in-flight requests the peer's GOAWAY did not cover
    val clientStreams = HashMap<Long, QuicStream>() // client: requests waiting for their response

    // RFC 9218 (server)
    val activeServerRequests = HashMap<Long, ServerRequestImpl>()
    private val earlyPriority = LinkedHashMap<Long, StreamPriority>() // PRIORITY_UPDATE for streams not open yet

    /** Server: the highest client bidirectional stream taken from the transport; the transport hands them out in id order. */
    private var acceptedBidiUpTo = -1L

    /** Server: client bidirectional streams taken from the transport whose handler has not ended (HEADERS may still be on the way). */
    private val handledBidi = HashSet<Long>()
    private var peerMaxPushId = -1L // server: the client's last MAX_PUSH_ID (we never push; kept to catch a decrease)

    /** HEADERS frames above this are refused unread; QPACK output is never much larger than the decoded section it carries. */
    val maxHeadersFrame: Long get() = 2 * settings.maxFieldSectionSize

    /** Bytes of HEADERS payloads being read on request streams right now (a test hook; session dispatcher only). */
    var bufferedHeaderBytes = 0L

    /** Completes once our control and QPACK streams are open and typed and our SETTINGS went out. */
    private val criticalStreams = CompletableDeferred<Unit>()

    /**
     * Starts the session. A coroutine of the session opens our control and QPACK streams: opening a stream waits for the
     * peer's stream credit (RFC 9000 section 4.6), and a peer whose transport parameters allow fewer than the three
     * unidirectional streams HTTP/3 needs (RFC 9114 section 6.2: they "MUST allow the peer to create at least three") would
     * hold the caller forever. Without them after [criticalStreamsDeadline] the connection closes with
     * H3_GENERAL_PROTOCOL_ERROR. A server returns at once, so an accept loop never waits on one peer; a client returns once
     * its SETTINGS went out and throws the connection's error when the streams could not be opened. A client that received
     * GOAWAY first (a server stopping right after the handshake) returns too: it closed itself, idle, as RFC 9114 section 5.2
     * lets it, and a request then fails with the retry-safe [Http3Exception.RequestNotProcessed]; its own H3_NO_ERROR close,
     * or the server's that came first, is no failure of the connection to report. Every other error still fails the start.
     */
    suspend fun start(criticalStreamsDeadline: Duration = CRITICAL_STREAMS_DEADLINE) {
        scope.launch {
            val e = quic.closed.await()
            onTransportClosed(e)
        }
        scope.launch { guarded { openCriticalStreams(criticalStreamsDeadline) } }
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            quic.pathEvents.collect { if (it is PathEvent.Changed) currentPath = it.new }
        }
        // each path reports its own peer address: a change before the collector started (a NAT rebinding right after the handshake)
        // must not leave the session on the path the peer left
        val active = quic.stats.currentPath
        quic.paths.firstOrNull { it.id == active }?.let { currentPath = it }
        scope.launch { acceptLoop() }
        datagrams.start()
        if (isServer) return
        try {
            awaitCriticalStreams()
        } catch (e: Http3Exception) {
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

    private suspend fun openCriticalStreams(deadline: Duration) {
        // RFC 9114 section 6.2: the critical streams first, then others (GREASE) as the peer allows
        val opened =
            withTimeoutOrNull(deadline) {
                control = quic.openUni(CRITICAL)
                encoderStream = quic.openUni(CRITICAL)
                decoderStream = quic.openUni(CRITICAL)
                controlLock.withLock {
                    control.output.writeFully(VarInt.encode(StreamType.CONTROL))
                    control.output.writeFully(FrameHeaders.frame(FrameType.SETTINGS, SettingsCodec.encode(ourSettings())))
                    if (settings.grease) {
                        control.output.writeFully(
                            FrameHeaders.frame(FrameType.grease(Random.nextLong(0, 1000)), Random.nextBytes(Random.nextInt(0, 8))),
                        )
                    }
                    control.output.flush()
                }
                encoderLock.withLock {
                    encoderStream.output.writeFully(VarInt.encode(StreamType.QPACK_ENCODER))
                    encoderStream.output.flush()
                }
                decoderLock.withLock {
                    decoderStream.output.writeFully(VarInt.encode(StreamType.QPACK_DECODER))
                    decoderStream.output.flush()
                }
                true
            }
        if (opened == null) {
            fail(
                Http3ErrorCode.GENERAL_PROTOCOL_ERROR,
                "control and QPACK streams not open after $deadline: the peer must allow at least three unidirectional streams",
            )
            return
        }
        criticalStreams.complete(Unit)
        // the peer stops a reserved stream at once (RFC 9114 section 6.2.3), so failures here are expected and never fatal
        if (settings.grease) {
            scope.launch {
                try {
                    val g = quic.openUni()
                    g.output.writeFully(VarInt.encode(FrameType.grease(Random.nextLong(0, 1000))) + Random.nextBytes(Random.nextInt(0, 8)))
                    g.output.flushAndClose()
                } catch (
                    e: CancellationException,
                ) {
                    throw e
                } catch (_: Throwable) {
                }
            }
        }
    }

    /** Waits until our control and QPACK streams exist; throws the connection's error if it closes first. */
    private suspend fun awaitCriticalStreams() {
        if (criticalStreams.isCompleted) return
        select {
            criticalStreams.onAwait { }
            closed.onAwait { throw it }
        }
    }

    /** The peer's SETTINGS; waits for them, or throws the connection's error if it closes first. */
    suspend fun awaitPeerSettings(): Http3PeerSettings =
        select {
            peerSettingsArrived.onAwait { it }
            closed.onAwait { throw it }
        }

    private fun ourSettings(): List<Pair<Long, Long>> =
        buildList {
            if (settings.qpackMaxTableCapacity > 0) add(SettingsId.QPACK_MAX_TABLE_CAPACITY to settings.qpackMaxTableCapacity)
            if (settings.qpackBlockedStreams > 0) add(SettingsId.QPACK_BLOCKED_STREAMS to settings.qpackBlockedStreams)
            add(SettingsId.MAX_FIELD_SECTION_SIZE to settings.maxFieldSectionSize)
            if (settings.enableConnectProtocol) add(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L)
            add(SettingsId.H3_DATAGRAM to if (settings.h3Datagram) 1L else 0L)
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
            if (!closed.isCompleted) {
                fail(
                    Http3ErrorCode.INTERNAL_ERROR,
                    e.message ?: e::class.simpleName ?: "internal error",
                )
            }
        }
    }

    private suspend fun acceptLoop() {
        while (true) {
            val st =
                try {
                    quic.acceptStream()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    return
                }
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
                            earlyPriority.remove(st.id) // a stream that never became a request (aborted) keeps no slot
                        }
                    },
                    st,
                )
            } else {
                fail(Http3ErrorCode.STREAM_CREATION_ERROR, "server-initiated bidirectional stream ${st.id}")
                return
            }
        }
    }

    /**
     * One of the peer's unidirectional streams. A stream that ends or is reset before its type is dropped: RFC 9114 section
     * 6.2 says "A receiver MUST tolerate unidirectional streams being closed or reset prior to the reception of the
     * unidirectional stream header" (quic-go's `handleUnidirectionalStream` returns the same way). Each such stream spends
     * a glitch token, so a peer that only opens and abandons streams still meets H3_EXCESSIVE_LOAD (section 10.5).
     */
    private suspend fun readUni(st: QuicStream) {
        val type =
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
                discardedUniStreams.value++
                glitch("unidirectional stream ended or reset before its type")
                return
            }
        when (type) {
            StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER -> {
                if (!peerUni.add(type)) throw H3ProtocolError(Http3ErrorCode.STREAM_CREATION_ERROR, "second stream of type $type")
                criticalStreamsSeen.value++
                try {
                    when (type) {
                        StreamType.CONTROL -> {
                            readControl(st)
                        }

                        StreamType.QPACK_ENCODER -> {
                            peerEncoderReading = true
                            try {
                                readQpack(st) { b, n -> qpack.onPeerEncoderStream(b, n) }
                            } finally {
                                peerEncoderReading = false
                            }
                        }

                        else -> {
                            readQpack(st) { b, n -> qpack.onPeerDecoderStream(b, n) }
                        }
                    }
                } catch (
                    e: IncompleteFrame,
                ) {
                    throw H3ProtocolError(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "critical stream $type closed")
                } catch (
                    e: QuicException.StreamError,
                ) {
                    throw H3ProtocolError(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "critical stream $type reset")
                }
                throw H3ProtocolError(Http3ErrorCode.CLOSED_CRITICAL_STREAM, "critical stream $type closed")
            }

            // no push: a client never sent MAX_PUSH_ID (so any push ID is too large); a server never receives push streams
            StreamType.PUSH -> {
                throw H3ProtocolError(if (isServer) Http3ErrorCode.STREAM_CREATION_ERROR else Http3ErrorCode.ID_ERROR, "push stream")
            }

            else -> {
                st.stopSending(Http3ErrorCode.STREAM_CREATION_ERROR)
                discardedUniStreams.value++
            } // unknown or reserved type: not a connection error (RFC 9114 section 6.2)
        }
    }

    private suspend fun readQpack(
        st: QuicStream,
        sink: suspend (ByteArray, Int) -> Unit,
    ) {
        val buf = ByteArray(4096)
        while (true) {
            val n = st.input.readAvailable(buf, 0, buf.size)
            if (n <
                0
            ) {
                st.input.closedCause?.let { throw it }
                return
            }
            if (n > 0) sink(buf, n)
        }
    }

    private suspend fun readControl(st: QuicStream) {
        var first = true
        while (true) {
            val type = st.input.readVarIntOrNull() ?: return
            val len = st.input.readVarInt()
            when (FrameRules.checkControl(type, first, isServer)) {
                FrameAction.Skip -> {
                    glitch("unknown frame on the control stream")
                    st.input.skipExact(len)
                }

                FrameAction.Process -> {
                    FrameRules.checkControlLength(type, len)
                    onControlFrame(type, st.input.readExact(len.toInt()))
                }
            }
            first = false
        }
    }

    private suspend fun onControlFrame(
        type: Long,
        payload: ByteArray,
    ) {
        when (type) {
            FrameType.SETTINGS -> {
                applyPeerSettings(SettingsCodec.decode(payload))
            }

            FrameType.GOAWAY -> {
                onGoAway(ControlFrames.parseGoAway(payload))
            }

            FrameType.PRIORITY_UPDATE_REQUEST -> {
                onPriorityUpdate(payload)
            }

            // server only (a client gets H3_FRAME_UNEXPECTED from FrameRules); RFC 9114 section 7.2.7
            FrameType.MAX_PUSH_ID -> {
                val id = ControlFrames.parseMaxPushId(payload)
                if (id < peerMaxPushId) throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "MAX_PUSH_ID fell from $peerMaxPushId to $id")
                peerMaxPushId = id
            }

            FrameType.PRIORITY_UPDATE_PUSH -> {
                throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PRIORITY_UPDATE for a push without server push")
            }

            else -> {}
        }
    }

    /**
     * Throws [Http3Exception.FieldSectionTooLarge] when [fields] (pseudo-headers included) exceed the peer's
     * `SETTINGS_MAX_FIELD_SECTION_SIZE`, counted as name + value + 32 per field (RFC 9114 section 4.2.2): the peer would
     * refuse it anyway. No limit is known before the peer's SETTINGS arrive.
     */
    fun checkPeerFieldLimit(
        streamId: Long,
        fields: List<Pair<String, String>>,
    ) {
        val limit = peerSettings.value?.maxFieldSectionSize ?: return
        var size = 0L
        for ((n, v) in fields) {
            size += entrySize(n, v)
            if (size > limit) throw Http3Exception.FieldSectionTooLarge(streamId, limit)
        }
    }

    private suspend fun applyPeerSettings(m: Map<Long, Long>) {
        val known =
            setOf(
                SettingsId.QPACK_MAX_TABLE_CAPACITY,
                SettingsId.QPACK_BLOCKED_STREAMS,
                SettingsId.MAX_FIELD_SECTION_SIZE,
                SettingsId.ENABLE_CONNECT_PROTOCOL,
                SettingsId.H3_DATAGRAM,
            )
        val ps =
            Http3PeerSettings(
                m[SettingsId.QPACK_MAX_TABLE_CAPACITY] ?: 0,
                m[SettingsId.QPACK_BLOCKED_STREAMS] ?: 0,
                m[SettingsId.MAX_FIELD_SECTION_SIZE],
                m[SettingsId.ENABLE_CONNECT_PROTOCOL] == 1L,
                m[SettingsId.H3_DATAGRAM] == 1L,
                m.filterKeys { it !in known },
            )
        // RFC 9297 section 2.1.1: H3_DATAGRAM=1 needs the transport's max_datagram_frame_size
        if (ps.h3Datagram &&
            quic.maxDatagramSize.value == 0
        ) {
            throw H3ProtocolError(Http3ErrorCode.SETTINGS_ERROR, "H3_DATAGRAM without QUIC datagram support")
        }
        qpack.onPeerSettings(ps.qpackMaxTableCapacity, ps.qpackBlockedStreams)
        peerSettings.value = ps
        peerSettingsArrived.complete(ps)
    }

    private fun onGoAway(id: Long) {
        val prev = goAwayReceived.value
        if (prev != null && id > prev) throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "GOAWAY id grew from $prev to $id")
        if (!isServer &&
            id % 4 != 0L
        ) {
            throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "GOAWAY $id is not a client-initiated bidirectional stream")
        }
        goAwayReceived.value = id
        if (!isServer) {
            for ((sid, st) in clientStreams.toList()) {
                if (sid >= id) { // never processed: fail them as retry-safe (section 5.2)
                    rejectedByGoAway += sid
                    runCatching { st.stopSending(Http3ErrorCode.REQUEST_CANCELLED) }
                    runCatching { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                }
            }
            closeIfIdleAfterGoAway()
        }
    }

    /**
     * RFC 9218 section 7 on a server: the client's new signal for a request stream. An open request takes it at once; a
     * stream whose request is not open yet (not opened, or its HEADERS still on the way) keeps it (at most
     * `maxEarlyPriorityUpdates`) and applies it when it opens; a stream beyond the limit we granted is H3_ID_ERROR
     * (section 7.2); frames above 256 bytes and the excess are ignored and spend glitch tokens.
     */
    private fun onPriorityUpdate(payload: ByteArray) {
        glitch("PRIORITY_UPDATE")
        if (payload.size > MAX_PRIORITY_UPDATE) {
            glitch("oversized PRIORITY_UPDATE")
            return
        }
        val (id, value) = ControlFrames.parsePriorityUpdate(payload)
        if (id % 4 != 0L) throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PRIORITY_UPDATE for stream $id, not a request stream")
        val p = PriorityField.parse(value)
        activeServerRequests[id]?.let {
            it.onPriorityUpdate(p)
            return
        }
        // the transport hands streams out in id order: one taken whose handler ended is over
        if (id <= acceptedBidiUpTo && id !in handledBidi) return
        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
        QuicStreamLimits.peerBidiStreamsGranted(quic)?.let {
            if (id / 4 >=
                it
            ) {
                throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PRIORITY_UPDATE for stream $id beyond the limit of $it streams")
            }
        }
        if (id in earlyPriority ||
            earlyPriority.size < settings.maxEarlyPriorityUpdates
        ) {
            earlyPriority[id] = p
        } else {
            glitch("early PRIORITY_UPDATE beyond the buffer")
        }
    }

    fun takeEarlyPriority(id: Long): StreamPriority? = earlyPriority.remove(id)

    /** Spends a glitch token; an empty bucket is a connection error H3_EXCESSIVE_LOAD (RFC 9114 section 8.1). */
    fun glitch(what: String) {
        val g =
            glitch ?: return
        if (!g.spend(glitchClock())) {
            throw H3ProtocolError(Http3ErrorCode.EXCESSIVE_LOAD, "too much useless work: $what")
        }
    }

    /**
     * Graceful shutdown (RFC 9114 section 5.2). A server sends GOAWAY(2^62-4), waits about two round trips for requests in
     * flight, then GOAWAY with the first id it will not process, and closes with H3_NO_ERROR once its accepted requests
     * are answered. A client sends GOAWAY(0) (no push) and stops issuing requests.
     */
    suspend fun goAway(): Unit = withContext(dispatcher) { goAwayConfined() }

    /** Runs on the session dispatcher right after a request's exchange was set up, before `request` returns (test hook). */
    internal var afterRequestForTest: (() -> Unit)? = null

    /** The context [goAway] ran in (test hook). */
    internal var goAwayContextForTest: ((kotlin.coroutines.CoroutineContext) -> Unit)? = null

    private suspend fun goAwayConfined() {
        goAwayContextForTest?.invoke(currentCoroutineContext())
        if (goAwayPhase != 0 || closed.isCompleted) return
        if (!isServer) {
            goAwayPhase = 2
            goAwaySentId = 0
            sendGoAway(0)
            return
        }
        goAwayPhase = 1
        if (!sendGoAway((1L shl 62) - 4)) return
        delay(maxOf(quic.stats.smoothedRtt * 2, 50.milliseconds))
        val id = if (maxRequestId < 0) 0 else maxRequestId + 4
        goAwayPhase = 2
        goAwaySentId = id
        if (!sendGoAway(id)) return
        // a request below the GOAWAY id whose HEADERS never complete must not hold the connection open forever
        scope.launch {
            delay(headerDeadlineAfterGoAway)
            headerDeadlinePassed = true
            for ((st, reader) in pendingHeaders.values.toList()) {
                abort(st, Http3ErrorCode.REQUEST_REJECTED)
                reader.cancel()
            }
        }
        scope.launch { closeIfIdle() }
    }

    /**
     * GOAWAY([id]) on our control stream; false when the connection closed meanwhile, which ends the graceful shutdown
     * (a client idle after our first GOAWAY closes at once, RFC 9114 section 5.2).
     */
    private suspend fun sendGoAway(id: Long): Boolean =
        try {
            sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(id))
            true
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // the connection ended under the write (an idle client closes as soon as GOAWAY arrives): the transport's loss can
            // reach this write before the session's own close has run, so it counts as closed too
            if (closed.isCompleted || transportCause(e) is QuicException.ConnectionLost) false else throw e
        }

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

    /**
     * After the final GOAWAY with nothing in flight and every response acknowledged (RFC 9114 section 5.2): the client
     * closes the connection once it read its responses (quic-go's server waits for exactly that); one that does not is
     * closed after [goAwayCloseFallback], so a slow reader of an acknowledged response still has that long.
     */
    private suspend fun closeIfIdle() {
        if (activeRequests > 0 || settling > 0 || closed.isCompleted) return
        delay(maxOf(quic.stats.smoothedRtt * 4, goAwayCloseFallback))
        if (activeRequests == 0 && settling == 0) close(Http3ErrorCode.NO_ERROR, "")
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
     * Client: a GOAWAY was received and no exchange is left, so this connection carries nothing more (no new request may
     * use it): close it with H3_NO_ERROR (RFC 9114 section 5.2), which is what lets the server finish its graceful stop
     * without guessing whether our responses were read.
     */
    private fun closeIfIdleAfterGoAway() {
        if (isServer || goAwayReceived.value == null || openExchanges > 0 || closed.isCompleted) return
        scope.launch {
            beforeIdleCloseForTest?.invoke(this@H3Session)
            close(Http3ErrorCode.NO_ERROR, "")
        }
    }

    /** Sends a frame on our control stream. */
    suspend fun sendControl(
        type: Long,
        payload: ByteArray,
    ) {
        awaitCriticalStreams()
        controlLock.withLock {
            control.output.writeFully(FrameHeaders.frame(type, payload))
            control.output.flush()
        }
    }

    /** Connection error (RFC 9114 section 8): close with [code], fail everything waiting. */
    suspend fun fail(
        code: Long,
        reason: String,
    ) {
        if (!closed.complete(Http3Exception.Protocol(code, Initiator.Local, null, "${Http3ErrorCode.name(code)}: $reason"))) return
        requests.close(closed.getCompleted())
        try {
            quic.close(code, reason.take(200))
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
        }
    }

    suspend fun close(
        code: Long,
        reason: String,
    ) {
        if (closed.complete(
                Http3Exception.Protocol(code, Initiator.Local, null, "closed locally with ${Http3ErrorCode.name(code)}"),
            )
        ) {
            requests.close(closed.getCompleted())
        }
        try {
            quic.close(code, reason)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Throwable) {
        }
    }

    /**
     * [job] reads a peer's stream (a message body, a unidirectional stream): when the connection is lost it goes on until
     * its input ends, which it does once it has read what the peer sent before the loss (`QuicStream.input`), so a
     * response whose last bytes came with the peer's CONNECTION_CLOSE is still read whole. [stream] is the stream of the
     * message it reads: one that came whole is never cut ([onTransportClosed]). Session dispatcher only.
     */
    fun drains(
        job: Job,
        stream: QuicStream? = null,
    ): Job {
        if (drainers.size >= drainersPruneAt) {
            drainers.removeAll { it.job.isCompleted }
            drainersPruneAt = maxOf(DRAINERS_PRUNE_MIN, drainers.size * 2)
        }
        drainers += Drainer(job, stream)
        return job
    }

    /**
     * The connection is gone: every coroutine of the session ends, but the [drains] readers only once their inputs ended.
     * Cancelling them at once lost what the peer sent last, Firefox's WT_CLOSE_SESSION right before its close. A reader of
     * a stream that came whole (its FIN and every byte before it, RFC 9000 section 3.2 "Data Recvd") goes on until it has
     * handed all of it over: that is the peer's complete message (it ends with its stream, RFC 9114 section 4.1), and
     * the close does not take back what had arrived. Reading it needs nothing more from the network, and the reader does
     * not wait for the application either ([handOver]): it moves the rest into the body and ends, so the session ends
     * whether or not the application reads, and the bytes live only as long as the application keeps the body. Every
     * other reader gets at most [DRAIN_GRACE] (one the application does not keep up with is cut there, never holding the
     * session for a message that cannot complete).
     */
    private fun onTransportClosed(e: QuicException.ConnectionLost) {
        if (closed.complete(Http3Exception.fromQuic(e))) requests.close(closed.getCompleted())
        val draining = drainers.filter { it.job.isActive }
        drainers.clear()
        if (draining.isEmpty()) {
            job.cancel()
            return
        }
        val readers = draining.map { it.job }.toSet()
        for (c in job.children.toList()) if (c !in readers) c.cancel()
        // read once the transport reported the end, which it does after it settled which streams came whole
        val partial = draining.filter { it.stream?.receivedAll != true }.map { it.job }
        scope.launch {
            if (partial.isNotEmpty()) {
                launch(start = CoroutineStart.UNDISPATCHED) {
                    drainTimer(DRAIN_GRACE)
                    for (r in partial) r.cancel()
                }
            }
            for (r in readers) r.join()
            job.cancel()
        }
    }

    /**
     * Launches a reader of a peer's stream that may finish it when the connection is lost, like a [drains] one, from any
     * thread. It runs outside [scope]: a launch into the scope once the connection ended never runs, and a response whose
     * headers were read after the session processed the peer's CONNECTION_CLOSE lost its body that way (seen on slow
     * Windows and macOS runners). Once the session's coroutines are gone it gets at most [DRAIN_GRACE] more, then it is
     * cut, unless [stream], the stream it reads, came whole: then it goes on until it has handed all of it over (without
     * waiting for the application, [handOver]), however late it runs (a reader the scheduler paused past the grace cut a whole response with H3_NO_ERROR, seen on a loaded
     * Android 7 emulator).
     */
    fun launchDrainer(
        stream: QuicStream? = null,
        block: suspend CoroutineScope.() -> Unit,
    ): Job =
        afterEnd.launch {
            val reader =
                launch {
                    beforeDrainerForTest?.invoke()
                    block()
                }
            select {
                reader.onJoin {}
                job.onJoin {}
            }
            if (reader.isCompleted) return@launch
            val drainer = coroutineContext.job
            if (stream?.receivedAll != true) {
                // cut: this coroutine ends cancelled, the reader with it
                launch(start = CoroutineStart.UNDISPATCHED) {
                    drainTimer(DRAIN_GRACE)
                    drainer.cancel()
                }
            }
            reader.join()
            drainer.children.forEach { it.cancel() }
        }

    /**
     * Runs [cleanup] when [job] ends cancelled, with the connection's reason once it is gone. Unlike a catch or finally in
     * the job's body this also runs for a job cancelled before it started: a launch into the scope of a connection that
     * already ended runs none of its body, and a channel only it would have closed left its reader or writer waiting
     * forever (a response body whose pump was launched just after the connection closed). [cleanup] runs on whatever
     * thread cancels the job: it may only close channels and complete deferreds.
     */
    fun onCancelled(
        job: Job,
        cleanup: (Throwable) -> Unit,
    ) {
        job.invokeOnCompletion { e -> if (e != null) cleanup(if (closed.isCompleted) closed.getCompleted() else e) }
    }

    /** What a stream operation throws once the connection is gone. */
    fun connectionError(): Throwable = if (closed.isCompleted) closed.getCompleted() else IllegalStateException("connection open")

    /** Maps a transport failure seen on a stream to the exception the application gets. */
    fun map(e: Throwable): Throwable {
        if (e is Http3Exception) return e
        val q = transportCause(e) ?: return e // ktor-io wraps the cause of a failed write in ClosedWriteChannelException
        return if (q is QuicException.ConnectionLost && closed.isCompleted) closed.getCompleted() else Http3Exception.fromQuic(q)
    }

    companion object {
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

        private const val DRAINERS_PRUNE_MIN = 64

        /** Control and QPACK streams: sent before every request stream, whatever urgency a peer asks for. */
        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
        val CRITICAL = StreamPriority.Critical
        const val MAX_PRIORITY_UPDATE = 256

        fun transportCause(e: Throwable): QuicException? =
            generateSequence(e) {
                it.cause
            }.take(8).firstOrNull { it is QuicException } as QuicException?
    }
}
