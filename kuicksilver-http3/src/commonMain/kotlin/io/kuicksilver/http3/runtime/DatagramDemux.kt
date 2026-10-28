// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

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
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * HTTP datagrams of a connection (RFC 9297 section 2.1): one collector of the transport's datagrams, routed by quarter
 * stream ID to the streams that registered. Unknown IDs are dropped silently, but for a stream beyond the bidirectional
 * stream limit, which is a connection error H3_ID_ERROR; a datagram without a valid quarter stream ID is a connection
 * error H3_DATAGRAM_ERROR. A stream is unregistered when its receive side closes, so later
 * datagrams for it are dropped as the RFC requires. With WebTransport a server keeps datagrams for a request stream whose
 * CONNECT has not been read yet, bounded as early WebTransport streams are (draft-ietf-webtrans-http3 section 4.6).
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

    private suspend fun onDatagram(b: ByteArray) {
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
        // draft-ietf-webtrans-http3 section 4.6: a session's datagrams may overtake its CONNECT; kept, bounded as its
        // streams are (WtStreamRouter: 16 per connection, 5 s each). Others are dropped (RFC 9297 section 2.1).
        if (!session.isServer || !session.settings.webTransport || !session.requestMayStillOpen(streamId)) return
        prunePending()
        if (pending.size < MAX_PENDING) pending.addLast(Pending(streamId, payload, TimeSource.Monotonic.markNow() + PENDING_TIMEOUT))
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

    /** Stream [streamId] will not become a session (its handler ended): its waiting datagrams go. */
    fun dropPending(streamId: Long) {
        if (pending.isNotEmpty()) pending.removeAll { it.streamId == streamId }
    }

    private fun prunePending() {
        while (pending.isNotEmpty() && pending.first().expires.hasPassedNow()) pending.removeFirst()
    }

    /** Datagrams waiting for their stream's CONNECT (test hook; session dispatcher only). */
    val pendingCount: Int get() = pending.size

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
                DatagramSendResult.TooLarge(r.max - prefix.size)
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
                e.max - prefix.size,
            )
        }
    }

    companion object {
        const val QUEUE = 32

        /** Datagrams per connection that may wait for their session's CONNECT: the bound of the streams that wait. */
        const val MAX_PENDING = WtStreamRouter.MAX_BUFFERED_STREAMS

        /** How long one of them may wait. */
        val PENDING_TIMEOUT: Duration = WtStreamRouter.BUFFER_TIMEOUT

        /** Quarter stream IDs above 2^60 - 1 cannot name a client-initiated bidirectional stream. */
        const val MAX_QUARTER_ID = (1L shl 60) - 1
    }
}

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
        if (!sendOpen) DatagramSendResult.Closed else session.datagrams.trySend(st.id, payload)

    override suspend fun sendDatagram(payload: ByteArray) {
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
