// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.http3.runtime

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.CapsuleConfig
import io.kuicksilver.http3.CapsuleProtocol
import io.kuicksilver.http3.CapsuleStream
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.frame.H3ProtocolError
import io.kuicksilver.http3.message.CapsuleParser
import io.kuicksilver.http3.message.CapsuleRules
import io.kuicksilver.quic.DatagramSendResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.io.IOException
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.decrementAndFetch

/**
 * The Capsule Protocol on an Extended CONNECT stream (RFC 9297 section 3). Three coroutines in the connection's scope:
 * a reader that runs the stream's input through [CapsuleParser] into a bounded channel (a full channel stops reading,
 * which holds the peer back through flow control), a forwarder of the stream's QUIC datagrams, and a single writer that
 * drains a bounded queue of encoded capsules, so capsules never interleave. DATAGRAM capsules and QUIC datagrams share
 * one drop-oldest queue. A parse error resets and stops the stream with H3_MESSAGE_ERROR and fails [capsules] with
 * [Http3Exception.MessageError].
 */
internal class CapsuleStreamImpl(
    override val stream: Http3StreamImpl,
    private val config: CapsuleConfig,
) : CapsuleStream {
    private val parser =
        CapsuleParser(
            maxCapsuleLength = config.maxCapsuleLength.toLong(),
            maxDatagramLength = config.maxDatagramLength.toLong(),
            known = config.knownTypes + CapsuleProtocol.DATAGRAM,
            terminal = config.terminalTypes,
        )
    private val incoming = Channel<Capsule>(config.receiveQueue)
    private val datagramQueue = Channel<ByteArray>(DatagramDemux.QUEUE, BufferOverflow.DROP_OLDEST)
    private val outgoing = Channel<ByteArray>(config.sendQueue)
    private val closing = AtomicBoolean(false)

    /** Set by STOP_SENDING from our side: the input then ends without the peer's FIN, which is not a clean end. */
    private val inputStopped = AtomicBoolean(false)
    private val failure = AtomicReference<Throwable?>(null)

    /** The reader and the forwarder; the datagram queue closes when both ended. */
    private val datagramSources = AtomicInt(2)
    private lateinit var reader: Job
    private lateinit var writer: Job

    override val capsules: Flow<Capsule> = incoming.receiveAsFlow()
    override val datagrams: Flow<ByteArray> = datagramQueue.receiveAsFlow()

    /**
     * Starts the coroutines. Their cleanup is in completion handlers, which run even for a coroutine cancelled before it
     * started (a connection already closed), so no flow is left open forever.
     */
    fun start() {
        writer = stream.scope.launch { writeLoop() }
        writer.invokeOnCompletion { fail(it?.let { e -> connectionClosed(e) } ?: return@invokeOnCompletion) }
        // read to the end of what the peer sent even when the connection is lost: its last capsule may come with its close
        reader = stream.drains(stream.scope.launch { readLoop() })
        reader.invokeOnCompletion {
            incoming.close(IOException("the stream's input was stopped or the connection closed", it))
            datagramSourceEnded()
        }
        // the application asked the peer to stop sending: nobody reads the capsules any more
        stream.onStopSending = {
            inputStopped.store(true)
            reader.cancel()
        }
        stream.scope
            .launch { stream.datagrams.collect { datagramQueue.trySend(it) } }
            .invokeOnCompletion { datagramSourceEnded() }
    }

    private suspend fun readLoop() {
        val input = stream.input
        val buf = ByteArray(READ_CHUNK)
        var end: Throwable? = null
        try {
            while (true) {
                val n = input.readAvailable(buf, 0, buf.size)
                if (n < 0) break
                var p = 0
                while (p < n) {
                    var got: Capsule? = null
                    p +=
                        parser.feedOne(buf, p, n - p) { type, value ->
                            if (type == CapsuleProtocol.DATAGRAM) datagramQueue.trySend(value) else got = Capsule(type, value)
                        }
                    got?.let { incoming.send(it) } // waits for the collector: one capsule held at a time
                }
            }
            input.closedCause?.let { throw it }
            if (inputStopped.load()) throw IOException("the stream's input was stopped (STOP_SENDING)")
            parser.endOfStream() // RFC 9297 section 3.3: a FIN inside a capsule is a malformed message
        } catch (e: H3ProtocolError) {
            end = malformed(e.message ?: "malformed capsule")
        } catch (e: CancellationException) {
            end = IOException("the stream's input was stopped or the connection closed", e) // never a clean end
            throw e
        } catch (e: Throwable) {
            end = e
        } finally {
            incoming.close(end)
        }
    }

    private fun malformed(reason: String): Http3Exception.MessageError {
        val e = Http3Exception.MessageError(stream.streamId, reason)
        fail(e)
        stream.reset(Http3ErrorCode.MESSAGE_ERROR)
        stream.stopSending(Http3ErrorCode.MESSAGE_ERROR)
        return e
    }

    private suspend fun writeLoop() {
        val out = stream.output
        try {
            for (first in outgoing) {
                out.writeFully(first)
                while (true) {
                    val next = outgoing.tryReceive().getOrNull() ?: break
                    out.writeFully(next)
                }
                out.flush()
            }
            out.flushAndClose()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            fail(e)
        }
    }

    /** The first failure wins; the queue is closed with it and emptied, which also releases suspended senders. */
    private fun fail(e: Throwable) {
        failure.compareAndSet(null, e)
        outgoing.close(failure.load())
        while (true) {
            if (outgoing.tryReceive().isFailure) break
        }
    }

    private fun connectionClosed(e: Throwable): Throwable =
        if (e is CancellationException) IOException("the connection closed before the capsules were written", e) else e

    private fun datagramSourceEnded() {
        if (datagramSources.decrementAndFetch() == 0) datagramQueue.close()
    }

    override suspend fun send(capsule: Capsule) {
        check(!closing.load()) { "the capsule stream ${stream.streamId} is closed" }
        enqueue(CapsuleRules.encode(capsule.type, capsule.value))
    }

    private suspend fun enqueue(bytes: ByteArray) {
        failure.load()?.let { throw it }
        try {
            outgoing.send(bytes)
        } catch (e: ClosedSendChannelException) {
            throw IllegalStateException("the capsule stream ${stream.streamId} is closed", e)
        }
    }

    /**
     * Whether a datagram goes as a DATAGRAM capsule: HTTP/3 datagrams are unsupported and the fallback is on. Before the
     * peer's SETTINGS arrive they count as unsupported (`PeerDoesNotSupport`), as for a plain stream: only a server that
     * accepted a CONNECT ahead of the client's SETTINGS sees that, and then sends capsules, which every peer accepts.
     */
    private fun viaCapsule(): Boolean = config.datagramFallback && stream.datagramsUnsupported() != null

    override fun trySendDatagram(payload: ByteArray): DatagramSendResult {
        if (closing.load() || failure.load() != null || !stream.sendOpen) return DatagramSendResult.Closed
        if (!viaCapsule()) return stream.trySendDatagram(payload) // TooLarge stays TooLarge (RFC 9297 section 3.5)
        val r = outgoing.trySend(CapsuleRules.encode(CapsuleProtocol.DATAGRAM, payload))
        return when {
            r.isSuccess -> DatagramSendResult.Sent
            r.isClosed -> DatagramSendResult.Closed
            else -> DatagramSendResult.QueueFull
        }
    }

    override suspend fun sendDatagram(payload: ByteArray) {
        check(!closing.load()) { "the capsule stream ${stream.streamId} is closed" }
        if (!viaCapsule()) return stream.sendDatagram(payload)
        check(
            stream.sendOpen,
        ) { "the send side of stream ${stream.streamId} is closed: HTTP datagrams are no longer sent (RFC 9297 section 2.1)" }
        enqueue(CapsuleRules.encode(CapsuleProtocol.DATAGRAM, payload))
    }

    override suspend fun close() {
        if (closing.compareAndSet(expectedValue = false, newValue = true)) outgoing.close()
        writer.join()
        failure.load()?.let { throw it }
    }

    private companion object {
        const val READ_CHUNK = 16_384
    }
}
