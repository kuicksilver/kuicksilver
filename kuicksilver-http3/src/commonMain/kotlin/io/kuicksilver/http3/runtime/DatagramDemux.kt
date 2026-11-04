// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.CapsuleStream
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ResponseWriter
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.message.CapsuleRules
import io.kuicksilver.http3.webtransport.WtStreamRouter
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.DatagramUnsupportedReason
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.receivedAll
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * HTTP datagrams of a connection (RFC 9297 section 2.1): one collector of the transport's datagrams, routed by quarter
 * stream ID to the streams that registered. Unknown IDs are dropped silently, but for a stream beyond the bidirectional
 * stream limit, which is a connection error H3_ID_ERROR; a datagram without a valid quarter stream ID is a connection
 * error H3_DATAGRAM_ERROR. A stream is unregistered when its receive side closes, so later datagrams for it are dropped as
 * the RFC requires. With WebTransport a server keeps datagrams for a request stream whose HEADERS have not been read yet:
 * draft-ietf-webtrans-http3-16 section 4.6, "WebTransport endpoints SHOULD buffer streams and datagrams until they can be
 * associated with an established session. To avoid resource exhaustion, endpoints MUST limit the number of buffered
 * streams and datagrams." At most [MAX_PENDING] per connection, the excess dropped ("a datagram MUST be dropped"), and
 * each for [pendingHold], on the order of a round trip, as RFC 9297 section 2.1 allows for a stream not yet created
 * ("buffer it temporarily (on the order of a round trip)").
 */
internal class DatagramDemux(
    private val session: H3Session,
) {
    private val streams = HashMap<Long, Channel<ByteArray>>()

    private class Pending(
        val streamId: Long,
        val payload: ByteArray,
        val expires: TimeMark,
    )

    /** WebTransport datagrams whose session's CONNECT HEADERS have not been read yet (draft section 4.6), oldest first. */
    private val pending = ArrayDeque<Pending>()

    fun start() {
        if (!session.settings.h3Datagram) return
        session.scope.launch {
            try {
                session.quic.datagrams.collect { onDatagram(it.data) }
            } catch (
                e: CancellationException,
            ) {
                throw e
            } catch (_: Throwable) {
            }
        }
    }

    /** Datagrams received so far (test hook; session dispatcher only). */
    var receivedCount = 0
        private set

    private suspend fun onDatagram(b: ByteArray) {
        receivedCount++
        val q = VarInt.read(b, 0, b.size)
        if (q < 0 ||
            q > MAX_QUARTER_ID
        ) {
            session.fail(Http3ErrorCode.DATAGRAM_ERROR, "datagram without a valid quarter stream ID")
            return
        }
        val streamId = q * 4
        val payload = b.copyOfRange(VarInt.encodedLength(b[0]), b.size)
        val ch = streams[streamId]
        if (ch != null) {
            ch.trySend(payload)
            return
        }
        // RFC 9297 section 2.1: "maps to a stream that cannot be created due to client-initiated bidirectional stream
        // limits, it SHOULD be treated as an HTTP/3 connection error of type H3_ID_ERROR"
        if (session.beyondBidiStreamLimit(streamId)) {
            session.fail(Http3ErrorCode.ID_ERROR, "datagram for stream $streamId beyond the bidirectional stream limit")
            return
        }
        if (session.abortRequestWithoutDatagrams(streamId)) return
        // draft-ietf-webtrans-http3-16 section 4.6: a session's datagrams may overtake its CONNECT; kept, 16 per connection
        // (as its streams, WtStreamRouter), each on the order of a round trip (RFC 9297 section 2.1). Others are dropped.
        if (!session.isServer || !session.settings.webTransport || !session.requestMayStillOpen(streamId)) return
        // RFC 9297 section 2.1: after the stream's receive side is closed a datagram "MUST be silently dropped". A request
        // whose HEADERS and FIN have all arrived (its HEADERS still QPACK-blocked) can never take one (review S2)
        if (session.pendingHeaders[streamId]?.first?.receivedAll == true) return
        prunePending()
        if (pending.size < MAX_PENDING) pending.addLast(Pending(streamId, payload, clock.markNow() + holdFor(streamId)))
    }

    /** How the hold of a kept datagram is measured; a test replaces it to move time by hand. Session dispatcher only. */
    var clock: TimeSource = TimeSource.Monotonic

    /**
     * How long a datagram for [streamId] may wait: [MAX_HOLD] for a stream that exists and whose HEADERS are on the way (a
     * large or QPACK-blocked section; draft-ietf-webtrans-http3-16 section 4.6 "SHOULD buffer ... until they can be
     * associated", bounded as early WebTransport streams are), [pendingHold] for a stream not created yet, which RFC 9297
     * section 2.1 allows to buffer only "on the order of a round trip" (review 2026-10-28 H3R-5).
     */
    private fun holdFor(streamId: Long): Duration = if (session.requestOpenWithoutHeaders(streamId)) MAX_HOLD else pendingHold()

    /** Replaces [pendingHold] when set (tests: holds that differ without moving the RTT). Session dispatcher only. */
    var pendingHoldForTest: Duration? = null

    /** How long a datagram kept now may wait for its stream's HEADERS: [pendingHold] of the connection's RTT estimate. */
    fun pendingHold(): Duration {
        pendingHoldForTest?.let { return it }
        val stats = session.quic.stats
        return pendingHold(stats.smoothedRtt, stats.rttVar)
    }

    fun register(streamId: Long): Channel<ByteArray> {
        val ch = Channel<ByteArray>(QUEUE, BufferOverflow.DROP_OLDEST)
        streams[streamId] = ch
        prunePending()
        if (pending.any { it.streamId == streamId }) {
            val mine = pending.filter { it.streamId == streamId }
            pending.removeAll { it.streamId == streamId }
            for (p in mine) ch.trySend(p.payload)
        }
        return ch
    }

    /**
     * Stream [streamId] will not become a session: its waiting datagrams go. Returns whether there were any still within their
     * hold (one past it was dropped already, as far as the peer can tell).
     */
    fun dropPending(streamId: Long): Boolean {
        prunePending()
        return pending.isNotEmpty() && pending.removeAll { it.streamId == streamId }
    }

    /**
     * Drops the datagrams whose hold ended. Holds follow the RTT estimate when each datagram arrives, so the queue is not in
     * expiry order: every entry is looked at (at most [MAX_PENDING]), not only the head (review 2026-10-28 H3R-3).
     */
    private fun prunePending() {
        if (pending.isNotEmpty()) pending.removeAll { it.expires.hasPassedNow() }
    }

    /** Datagrams waiting for their stream's CONNECT (test hook; session dispatcher only). */
    val pendingCount: Int get() = pending.size

    /** When the oldest waiting datagram's hold ends (test hook; session dispatcher only). */
    fun pendingDeadlineForTest(): TimeMark? = pending.firstOrNull()?.expires

    fun unregister(streamId: Long) {
        streams.remove(streamId)?.close()
    }

    /** Streams with a registered datagram channel (test hook; session dispatcher only). */
    val registeredCount: Int get() = streams.size

    /** Unsupported until both sides sent SETTINGS_H3_DATAGRAM=1 (section 2.1.1). */
    fun unsupported(): DatagramSendResult.Unsupported? =
        when {
            !session.settings.h3Datagram -> DatagramSendResult.Unsupported(DatagramUnsupportedReason.Disabled)
            session.peerSettings.value?.h3Datagram != true -> DatagramSendResult.Unsupported(DatagramUnsupportedReason.PeerDoesNotSupport)
            else -> null
        }

    fun trySend(
        streamId: Long,
        payload: ByteArray,
    ): DatagramSendResult {
        unsupported()?.let { return it }
        val prefix = VarInt.encode(streamId / 4)
        return when (val r = session.quic.trySendDatagram(prefix + payload)) {
            is DatagramSendResult.TooLarge -> {
                DatagramSendResult.TooLarge(httpDatagramMax(r.max, prefix.size))
            }

            else -> {
                r
            }
        }
    }

    suspend fun send(
        streamId: Long,
        payload: ByteArray,
    ) {
        when (val u = unsupported()) {
            is DatagramSendResult.Unsupported -> {
                throw QuicException.DatagramUnsupported(u.reason)
            }

            else -> {}
        }
        val prefix = VarInt.encode(streamId / 4)
        try {
            session.quic.sendDatagram(prefix + payload)
        } catch (
            e: QuicException.DatagramTooLarge,
        ) {
            throw QuicException.DatagramTooLarge(
                payload.size,
                httpDatagramMax(e.max, prefix.size),
            )
        }
    }

    companion object {
        const val QUEUE = 32

        /** Datagrams per connection that may wait for their session's CONNECT: the bound of the streams that wait. */
        const val MAX_PENDING = WtStreamRouter.MAX_BUFFERED_STREAMS

        /** The shortest hold: the RTT estimate of a fast path is below what scheduling the CONNECT's reader takes. */
        val MIN_HOLD: Duration = 50.milliseconds

        /** The longest hold, whatever the RTT estimate says (the bound early WebTransport streams have). */
        val MAX_HOLD: Duration = WtStreamRouter.BUFFER_TIMEOUT

        /** RFC 9000 section 18.2: the max_ack_delay of a peer that does not send the parameter. */
        private val DEFAULT_MAX_ACK_DELAY: Duration = 25.milliseconds

        /** RFC 9002 section 6.2.1, kGranularity. */
        private val GRANULARITY: Duration = 1.milliseconds

        /**
         * The hold of a datagram for a stream not created yet, "on the order of a round trip" (RFC 9297 section 2.1): one PTO
         * (RFC 9002 section 6.2.1, `smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay`, with the default
         * max_ack_delay), after which a lost CONNECT is sent again, plus one [smoothedRtt] for it to arrive; within
         * [MIN_HOLD] and [MAX_HOLD].
         */
        fun pendingHold(
            smoothedRtt: Duration,
            rttVar: Duration,
        ): Duration = (smoothedRtt * 2 + maxOf(rttVar * 4, GRANULARITY) + DEFAULT_MAX_ACK_DELAY).coerceIn(MIN_HOLD, MAX_HOLD)

        /**
         * The largest HTTP datagram payload a QUIC datagram of at most [quicMax] bytes carries after a Quarter Stream ID of
         * [prefix] bytes; 0 when even an empty one does not fit (a peer's max_datagram_frame_size of 2 leaves a QUIC maximum
         * of 0), never negative.
         */
        fun httpDatagramMax(
            quicMax: Int,
            prefix: Int,
        ): Int = (quicMax - prefix).coerceAtLeast(0)

        /** Quarter stream IDs above 2^60 - 1 cannot name a client-initiated bidirectional stream. */
        const val MAX_QUARTER_ID = (1L shl 60) - 1
    }
}

/**
 * Whether a request with [method] and `:protocol` [protocol] has HTTP datagram semantics (RFC 9297 section 2: "HTTP Datagrams
 * MUST only be sent with an association to an HTTP request that explicitly supports them"; one received for a request
 * without them aborts it). Only an Extended CONNECT does: a classic CONNECT is a TCP tunnel (RFC 9110 section 9.3.6) and
 * RFC 9220's `websocket` defines none, so neither does; other protocols (WebTransport, `connect-udp`, an application's own,
 * which the application serves through [Http3Stream]) do (review 2026-10-28 h3.md H3R-4).
 */
internal fun hasDatagramSemantics(
    method: String,
    protocol: String?,
): Boolean = method == "CONNECT" && protocol != null && !protocol.equals("websocket", ignoreCase = true)

/**
 * An Extended CONNECT stream: the request stream's data in both directions plus its datagrams.
 *
 * [status] is the 2xx that established it (the peer's on the client, ours on the server); [localHeaders] are the fields
 * we sent (the request's on the client, the response's on the server); [isClient] says which side we are. They let
 * [useCapsuleProtocol] check RFC 9297 section 3.2 on both messages.
 */
internal class Http3StreamImpl(
    private val session: H3Session,
    private val st: QuicStream,
    override val input: ByteReadChannel,
    private val writer: Http3ResponseWriter,
    private val incoming: Channel<ByteArray>,
    override val headers: Http3Headers,
    internal val status: Int,
    internal val localHeaders: Http3Headers,
    internal val isClient: Boolean,
    private val onReset: () -> Unit = {},
    /** False for a CONNECT whose protocol has no datagram semantics ([hasDatagramSemantics]): none are sent on it. */
    internal val datagramsAllowed: Boolean = true,
) : Http3Stream {
    /** The connection's scope, on its dispatcher: the capsule reader and writer run there. */
    internal val scope: CoroutineScope get() = session.scope

    /** [job] reads this stream: it may finish what the peer sent when the connection is lost (`H3Session.drains`). */
    internal fun drains(job: Job): Job = session.drains(job)

    private val capsulesInUse = AtomicBoolean(false)

    /** The connection's reason why HTTP/3 datagrams cannot be sent, or null when they can. */
    internal fun datagramsUnsupported(): DatagramSendResult.Unsupported? = session.datagrams.unsupported()

    @ExperimentalKuicksilverApi
    override fun useCapsuleProtocol(config: CapsuleConfig): CapsuleStream {
        val (peerStatus, localStatus) = if (isClient) status to null else null to status
        CapsuleRules.violation(localHeaders, localStatus)?.let { throw IllegalStateException("our own message: $it") }
        check(
            capsulesInUse.compareAndSet(expectedValue = false, newValue = true),
        ) { "useCapsuleProtocol() was already called on stream $streamId" }
        CapsuleRules.violation(headers, peerStatus)?.let { reason ->
            reset(Http3ErrorCode.MESSAGE_ERROR)
            stopSending(Http3ErrorCode.MESSAGE_ERROR)
            throw Http3Exception.MessageError(streamId, reason)
        }
        return CapsuleStreamImpl(this, config).also { it.start() }
    }

    override val streamId: Long get() = st.id
    override val output: ByteWriteChannel get() = writer.output
    override var priority: StreamPriority
        get() = st.priority
        set(v) {
            st.priority = v
        }
    override val datagrams: Flow<ByteArray> = incoming.receiveAsFlow()

    /** Set by [reset]; a closed [output] (FIN sent or failed) closes the send side too. */
    private var resetSent = false

    /** RFC 9297 section 2.1: datagrams go out only while the stream's send side is open. */
    internal val sendOpen: Boolean get() = !resetSent && !writer.output.isClosedForWrite && !st.output.isClosedForWrite

    override fun trySendDatagram(payload: ByteArray): DatagramSendResult =
        if (!datagramsAllowed || !sendOpen) DatagramSendResult.Closed else session.datagrams.trySend(st.id, payload)

    override suspend fun sendDatagram(payload: ByteArray) {
        check(datagramsAllowed) {
            "stream ${st.id} is a CONNECT whose protocol has no HTTP datagrams (classic CONNECT, websocket): none are sent (RFC 9297 section 2)"
        }
        check(sendOpen) { "the send side of stream ${st.id} is closed: HTTP datagrams are no longer sent (RFC 9297 section 2.1)" }
        session.datagrams.send(st.id, payload)
    }

    override fun reset(code: Long) {
        resetSent = true
        st.reset(code)
        onReset()
    }

    /** Called by [stopSending]: the Capsule Protocol reader stops, since the application gave up on the input. */
    @Volatile internal var onStopSending: (() -> Unit)? = null

    override fun stopSending(code: Long) {
        onStopSending?.invoke() // first: the input's end that follows must not read as the peer's clean FIN
        st.stopSending(code)
    }
}
