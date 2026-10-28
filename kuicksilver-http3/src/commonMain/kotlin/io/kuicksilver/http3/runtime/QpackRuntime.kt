// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.qpack.DecodeResult
import io.kuicksilver.http3.qpack.QpackDecoder
import io.kuicksilver.http3.qpack.QpackEncoder
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration.Companion.milliseconds

/** The stream of a blocked field section was reset by the peer while it waited. */
internal class StreamAbandoned : Exception("stream abandoned while blocked")

/**
 * QPACK of one connection (RFC 9204 section 2): the codecs plus the order rules between their streams. Encoder-stream
 * instructions are written before the field section that needs them; decoder-stream instructions leave after each
 * decoded section or batch of inserts. Runs on the session's single-threaded dispatcher.
 */
internal class QpackRuntime(
    settings: Http3Settings,
    private val encoderOut: suspend (ByteArray) -> Unit,
    private val decoderOut: suspend (ByteArray) -> Unit,
) {
    private val encoder = QpackEncoder(settings.encoderMaxTableCapacity)
    private val decoder = QpackDecoder(settings.qpackMaxTableCapacity, settings.qpackBlockedStreams.toInt(), settings.maxFieldSectionSize)
    private val encLock = Mutex()
    private val decLock = Mutex()
    private val inserts = MutableStateFlow(0L)

    /** Bytes the last field section cost (its block plus the encoder-stream instructions it needed) and inserts made by our encoder. */
    var lastEncodedSize: Int = 0
        private set
    val encoderInserts: Long get() = encoder.insertCount

    /** Stream Cancellations the peer's decoder sent our encoder (a test hook). */
    val peerStreamCancellations: Long get() = encoder.streamCancellationsReceived

    suspend fun onPeerSettings(
        peerMaxTableCapacity: Long,
        peerBlockedStreams: Long,
    ) = encLock.withLock {
        encoder.onPeerSettings(peerMaxTableCapacity, peerBlockedStreams)
        val b = encoder.drainEncoderStream()
        if (b.isNotEmpty()) encoderOut(b)
    }

    suspend fun encode(
        streamId: Long,
        fields: List<Pair<String, String>>,
    ): ByteArray =
        encLock.withLock {
            val block = encoder.encode(streamId, fields)
            val ins = encoder.drainEncoderStream()
            if (ins.isNotEmpty()) encoderOut(ins)
            lastEncodedSize = block.size + ins.size
            block
        }

    /**
     * Decoded or TooLarge; a blocked section waits for the encoder stream (QpackError when the blocked-stream budget is
     * exceeded). While it waits, [abandoned] is polled: a stream the peer reset is cancelled (RFC 9204 section 4.4.2) and
     * [StreamAbandoned] is thrown.
     */
    suspend fun decode(
        streamId: Long,
        block: ByteArray,
        abandoned: () -> Boolean = { false },
    ): DecodeResult {
        while (true) {
            when (val r = decoder.decode(streamId, block)) {
                is DecodeResult.Blocked -> {
                    decoder.markBlocked(streamId)
                    while (withTimeoutOrNull(BLOCKED_POLL) { inserts.first { it >= r.requiredInsertCount } } == null) {
                        if (abandoned()) {
                            cancelStream(streamId)
                            throw StreamAbandoned()
                        }
                    }
                }

                else -> {
                    flushDecoder()
                    return r
                }
            }
        }
    }

    suspend fun onPeerEncoderStream(
        bytes: ByteArray,
        len: Int,
    ) {
        decoder.onEncoderStream(bytes, 0, len)
        inserts.value =
            decoder.insertCount
        flushDecoder()
    }

    suspend fun onPeerDecoderStream(
        bytes: ByteArray,
        len: Int,
    ) = encLock.withLock { encoder.onDecoderStream(bytes, 0, len) }

    /**
     * Client, the server rejected 0-RTT (RFC 9001 section 4.6.2): what the codecs hold unsent was made for the early streams
     * the server never saw, and goes. Before the handshake completes nothing of the server has been read, so the decoder
     * can only hold Stream Cancellations of early requests, and the encoder, which knows no peer SETTINGS yet, nothing (it
     * may use the dynamic table only after them, RFC 9204 section 3.2.3, and this client stores no settings for 0-RTT).
     */
    fun onEarlyDataRejected() {
        decoder.drainDecoderStream()
        encoder.drainEncoderStream()
    }

    /** The stream was abandoned before its field sections were all decoded. */
    suspend fun cancelStream(streamId: Long) {
        decoder.cancelStream(streamId)
        flushDecoder()
    }

    private companion object {
        val BLOCKED_POLL = 50.milliseconds
    }

    private suspend fun flushDecoder() =
        decLock.withLock {
            val b = decoder.drainDecoderStream()
            if (b.isNotEmpty()) decoderOut(b)
        }
}
