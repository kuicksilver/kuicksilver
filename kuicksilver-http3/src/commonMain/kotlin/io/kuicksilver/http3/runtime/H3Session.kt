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
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicPath
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds
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
    private val job = SupervisorJob()
    val scope = CoroutineScope(job + dispatcher + CoroutineName("http3"))
    val peerSettings = MutableStateFlow<Http3PeerSettings?>(null)
    private val peerSettingsArrived = CompletableDeferred<Http3PeerSettings>()
    val datagrams = DatagramDemux(this)
    val goAwayReceived = MutableStateFlow<Long?>(null)
    val closed = CompletableDeferred<Throwable>()
    val requests = Channel<ServerRequestImpl>(Channel.UNLIMITED)

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
                encoderLock.withLock {
                    encoderStream.output.writeFully(b)
                    encoderStream.output.flush()
                }
            },
            { b ->
                decoderLock.withLock {
                    decoderStream.output.writeFully(b)
                    decoderStream.output.flush()
                }
            },
        )
    private val peerUni = HashSet<Long>() // stream types seen: one control, one encoder, one decoder
    private val glitch = if (settings.glitchProtection) GlitchLimiter() else null
    private val clock = TimeSource.Monotonic.markNow()

    // GOAWAY (RFC 9114 section 5.2)
    private var goAwayPhase = 0 // 0 none, 1 first (2^62-4) sent, 2 final sent

    /** Server: requests with ids from here on are rejected; client: 0 once we sent ours. */
    var goAwaySentId: Long? = null
        private set
    var maxRequestId = -1L // server: highest client stream id seen
    private var activeRequests = 0 // server: accepted requests whose response has not ended
    val rejectedByGoAway = HashSet<Long>() // client: in-flight requests the peer's GOAWAY did not cover
    val clientStreams = HashMap<Long, QuicStream>() // client: requests waiting for their response

    // RFC 9218 (server)
    val activeServerRequests = HashMap<Long, ServerRequestImpl>()
    private val earlyPriority = LinkedHashMap<Long, StreamPriority>() // PRIORITY_UPDATE for streams not open yet

    /** HEADERS frames above this are refused unread; QPACK output is never much larger than the decoded section it carries. */
    val maxHeadersFrame: Long get() = 2 * settings.maxFieldSectionSize

    /** Bytes of HEADERS payloads being read on request streams right now (a test hook; session dispatcher only). */
    var bufferedHeaderBytes = 0L

    suspend fun start() {
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
        scope.launch {
            val e = quic.closed.await()
            onTransportClosed(e)
        }
        scope.launch { quic.pathEvents.collect { if (it is PathEvent.Changed) currentPath = it.new } }
        scope.launch { acceptLoop() }
        datagrams.start()
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
            if (st.id and 2L != 0L) {
                scope.launch { guarded { readUni(st) } }
            } else if (isServer) {
                scope.launch { guarded { handleRequestStream(this@H3Session, st) } }
            } else {
                fail(Http3ErrorCode.STREAM_CREATION_ERROR, "server-initiated bidirectional stream ${st.id}")
                return
            }
        }
    }

    private suspend fun readUni(st: QuicStream) {
        val type =
            try {
                st.input.readVarIntOrNull()
            } catch (_: IncompleteFrame) {
                null
            } ?: run {
                glitch("empty unidirectional stream")
                return
            }
        when (type) {
            StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER -> {
                if (!peerUni.add(type)) throw H3ProtocolError(Http3ErrorCode.STREAM_CREATION_ERROR, "second stream of type $type")
                try {
                    when (type) {
                        StreamType.CONTROL -> readControl(st)
                        StreamType.QPACK_ENCODER -> readQpack(st) { b, n -> qpack.onPeerEncoderStream(b, n) }
                        else -> readQpack(st) { b, n -> qpack.onPeerDecoderStream(b, n) }
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

            FrameType.PRIORITY_UPDATE_PUSH -> {
                throw H3ProtocolError(Http3ErrorCode.ID_ERROR, "PRIORITY_UPDATE for a push without server push")
            }

            else -> {}
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
        }
    }

    /**
     * RFC 9218 section 7 on a server: the client's new signal for a request stream. An open request takes it at once; a
     * stream not open yet keeps it (at most `maxEarlyPriorityUpdates`); frames above 256 bytes and the excess are ignored
     * and spend glitch tokens.
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
        if (id <= maxRequestId) return // the request is over
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
        if (!g.spend(
                clock.elapsedNow().inWholeNanoseconds,
            )
        ) {
            throw H3ProtocolError(Http3ErrorCode.EXCESSIVE_LOAD, "too much useless work: $what")
        }
    }

    /**
     * Graceful shutdown (RFC 9114 section 5.2). A server sends GOAWAY(2^62-4), waits about two round trips for requests in
     * flight, then GOAWAY with the first id it will not process, and closes with H3_NO_ERROR once its accepted requests
     * are answered. A client sends GOAWAY(0) (no push) and stops issuing requests.
     */
    suspend fun goAway() {
        if (goAwayPhase != 0 || closed.isCompleted) return
        if (!isServer) {
            goAwayPhase = 2
            goAwaySentId = 0
            sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(0))
            return
        }
        goAwayPhase = 1
        sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload((1L shl 62) - 4))
        delay(maxOf(quic.stats.smoothedRtt * 2, 50.milliseconds))
        val id = if (maxRequestId < 0) 0 else maxRequestId + 4
        goAwayPhase = 2
        goAwaySentId = id
        sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(id))
        closeIfIdle()
    }

    fun requestStarted() {
        activeRequests++
    }

    fun requestDone() {
        activeRequests--
        if (goAwayPhase == 2) scope.launch { closeIfIdle() }
    }

    /** After the final GOAWAY with nothing in flight: give the last responses a few round trips to be acknowledged, then close. */
    private suspend fun closeIfIdle() {
        if (activeRequests > 0 || closed.isCompleted) return
        delay(maxOf(quic.stats.smoothedRtt * 4, 200.milliseconds))
        if (activeRequests == 0) close(Http3ErrorCode.NO_ERROR, "")
    }

    /** Sends a frame on our control stream. */
    suspend fun sendControl(
        type: Long,
        payload: ByteArray,
    ) = controlLock.withLock {
        control.output.writeFully(FrameHeaders.frame(type, payload))
        control.output.flush()
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

    private fun onTransportClosed(e: QuicException.ConnectionLost) {
        if (closed.complete(Http3Exception.fromQuic(e))) requests.close(closed.getCompleted())
        job.cancel()
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
        val CRITICAL = StreamPriority(0)
        const val MAX_PRIORITY_UPDATE = 256

        fun transportCause(e: Throwable): QuicException? =
            generateSequence(e) {
                it.cause
            }.take(8).firstOrNull { it is QuicException } as QuicException?
    }
}
