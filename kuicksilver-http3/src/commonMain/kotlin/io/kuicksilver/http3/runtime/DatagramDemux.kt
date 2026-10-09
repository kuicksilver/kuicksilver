// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3ResponseWriter
import io.kuicksilver.http3.Http3Stream
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.DatagramUnsupportedReason
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch

/**
 * HTTP datagrams of a connection (RFC 9297 section 2.1): one collector of the transport's datagrams, routed by quarter
 * stream ID to the streams that registered. Unknown IDs are dropped silently; a datagram without a valid quarter
 * stream ID is a connection error H3_DATAGRAM_ERROR.
 */
internal class DatagramDemux(
    private val session: H3Session,
) {
    private val streams = HashMap<Long, Channel<ByteArray>>()

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
        streams[q * 4]?.trySend(b.copyOfRange(VarInt.encodedLength(b[0]), b.size))
    }

    fun register(streamId: Long): Channel<ByteArray> = Channel<ByteArray>(QUEUE, BufferOverflow.DROP_OLDEST).also { streams[streamId] = it }

    fun unregister(streamId: Long) {
        streams.remove(streamId)?.close()
    }

    /** Streams with a registered datagram channel (test hook; session dispatcher only). */
    val registeredCount: Int get() = streams.size

    /** Unsupported until both sides sent SETTINGS_H3_DATAGRAM=1 (section 2.1.1). */
    private fun unsupported(): DatagramSendResult? =
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

        /** Quarter stream IDs above 2^60 - 1 cannot name a client-initiated bidirectional stream. */
        const val MAX_QUARTER_ID = (1L shl 60) - 1
    }
}

/** An Extended CONNECT stream: the request stream's data in both directions plus its datagrams. */
internal class Http3StreamImpl(
    private val session: H3Session,
    private val st: QuicStream,
    override val input: ByteReadChannel,
    private val writer: Http3ResponseWriter,
    private val incoming: Channel<ByteArray>,
    override val headers: Http3Headers,
    private val onReset: () -> Unit = {},
) : Http3Stream {
    override val streamId: Long get() = st.id
    override val output: ByteWriteChannel get() = writer.output
    override var priority: StreamPriority
        get() = st.priority
        set(v) {
            st.priority = v
        }
    override val datagrams: Flow<ByteArray> = incoming.receiveAsFlow()

    override fun trySendDatagram(payload: ByteArray): DatagramSendResult = session.datagrams.trySend(st.id, payload)

    override suspend fun sendDatagram(payload: ByteArray) {
        session.datagrams.send(st.id, payload)
    }

    override fun reset(code: Long) {
        st.reset(code)
        onReset()
    }

    override fun stopSending(code: Long) {
        st.stopSending(code)
    }
}
