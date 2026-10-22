// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.http3.message.CapsuleRules
import io.kuicksilver.quic.DatagramSendResult
import kotlinx.coroutines.flow.Flow

/**
 * One capsule of the Capsule Protocol (RFC 9297 section 3.2): a [type] and its whole [value]. Two capsules are equal when
 * their types and value bytes are.
 *
 * @property type the capsule type, 0..2^62-1 (a QUIC variable-length integer); 0x00 is DATAGRAM ([CapsuleProtocol.DATAGRAM]).
 * @property value the capsule's value; the array is not copied, so do not change it after handing the capsule over.
 */
@ExperimentalKuicksilverApi
public class Capsule(
    public val type: Long,
    public val value: ByteArray,
) {
    init {
        require(type in 0..CapsuleRules.MAX_TYPE) { "capsule type must be 0..2^62-1, was $type" }
    }

    override fun equals(other: Any?): Boolean = other is Capsule && other.type == type && other.value.contentEquals(value)

    override fun hashCode(): Int = 31 * type.hashCode() + value.contentHashCode()

    override fun toString(): String = "Capsule(type=0x${type.toString(16)}, ${value.size} bytes)"
}

/** Constants and the header field of the Capsule Protocol (RFC 9297 section 3). */
@ExperimentalKuicksilverApi
public object CapsuleProtocol {
    /** The `Capsule-Protocol` header field name (RFC 9297 section 3.4), lower case as HTTP/3 carries it. */
    public const val FIELD: String = CapsuleRules.FIELD

    /** The DATAGRAM capsule type (RFC 9297 section 3.5): an HTTP datagram carried on the stream itself. */
    public const val DATAGRAM: Long = 0x00

    /**
     * `capsule-protocol: ?1`, for a request's or response's fields. Protocols that define their use of capsules (such as
     * WebTransport or CONNECT-UDP) do not need it; it tells intermediaries that the data stream carries capsules.
     */
    public val Enabled: Pair<String, String> = FIELD to "?1"

    /**
     * Whether [headers] carry `Capsule-Protocol` as the Structured Field Boolean true (RFC 9297 section 3.4, RFC 8941):
     * `?1`, with any parameters, which are ignored. `?0`, another item type, a value that does not parse, or the field
     * given more than once is false.
     */
    public fun isEnabled(headers: Http3Headers): Boolean = CapsuleRules.isEnabled(headers)
}

/**
 * How an Extended CONNECT stream speaks the Capsule Protocol ([Http3Stream.useCapsuleProtocol]); build it with the
 * constructor, [capsuleConfig] or [Builder].
 *
 * Memory per stream is bounded by `receiveQueue * maxCapsuleLength` for received capsules, 32 datagrams of at most
 * `maxDatagramLength` bytes, and `sendQueue` capsules of the application's own size: unknown and oversized DATAGRAM
 * capsules are skipped as their bytes arrive, never buffered.
 *
 * @property knownTypes capsule types delivered in [CapsuleStream.capsules]; any other type is skipped silently (RFC 9297
 *   section 3.2), except DATAGRAM, which always goes to [CapsuleStream.datagrams]. Each in 0..2^62-1; empty by default.
 * @property maxCapsuleLength the longest capsule of a known type we accept, in bytes; a longer one is a malformed
 *   message (the stream is reset with H3_MESSAGE_ERROR). 1..1 048 576; 65 536 by default.
 * @property maxDatagramLength the longest DATAGRAM capsule we accept, in bytes; a longer one is dropped without being
 *   buffered (RFC 9297 section 3.5). 1..1 048 576; 65 536 by default.
 * @property datagramFallback send a datagram as a DATAGRAM capsule when HTTP/3 datagrams are unsupported on the
 *   connection (either side's `SETTINGS_H3_DATAGRAM` is 0); true by default. A datagram too large for a QUIC DATAGRAM
 *   frame is never turned into a capsule. Until the peer's SETTINGS arrive, HTTP/3 datagrams count as unsupported
 *   (`PeerDoesNotSupport`), though the peer may still turn them on: with the fallback such datagrams go as capsules,
 *   without it they are refused. A client's `connect` returns only after the server's SETTINGS, so only a server that
 *   accepts a CONNECT before the client's SETTINGS arrived sees this.
 * @property receiveQueue received capsules held for [CapsuleStream.capsules] before reading the stream pauses, which
 *   holds back the peer through flow control; 1..4096, 16 by default.
 * @property sendQueue capsules (DATAGRAM capsules included) waiting to be written before [CapsuleStream.send] suspends
 *   and a fallback [CapsuleStream.trySendDatagram] answers QueueFull; 1..4096, 32 by default.
 * @property terminalTypes types of [knownTypes] whose capsule ends the stream's data: it is delivered, and any byte
 *   after it (a capsule of any type, even one that would be skipped) is a malformed message, so the stream is reset
 *   with H3_MESSAGE_ERROR and [CapsuleStream.capsules] fails with [Http3Exception.MessageError]. For WebTransport's
 *   WT_CLOSE_SESSION (draft-ietf-webtrans-http3 section 6). Each must be in [knownTypes] and not DATAGRAM; empty by
 *   default.
 */
@ExperimentalKuicksilverApi
public class CapsuleConfig(
    public val knownTypes: Set<Long> = emptySet(),
    public val maxCapsuleLength: Int = 65_536,
    public val maxDatagramLength: Int = 65_536,
    public val datagramFallback: Boolean = true,
    public val receiveQueue: Int = 16,
    public val sendQueue: Int = 32,
    public val terminalTypes: Set<Long> = emptySet(),
) {
    init {
        require(knownTypes.all { it in 0..CapsuleRules.MAX_TYPE }) { "knownTypes must be 0..2^62-1" }
        require(maxCapsuleLength in 1..MAX_LENGTH) { "maxCapsuleLength must be 1..$MAX_LENGTH" }
        require(maxDatagramLength in 1..MAX_LENGTH) { "maxDatagramLength must be 1..$MAX_LENGTH" }
        require(receiveQueue in 1..MAX_QUEUE) { "receiveQueue must be 1..$MAX_QUEUE" }
        require(sendQueue in 1..MAX_QUEUE) { "sendQueue must be 1..$MAX_QUEUE" }
        require(terminalTypes.all { it in knownTypes && it != CapsuleProtocol.DATAGRAM }) {
            "terminalTypes must be among knownTypes and not DATAGRAM"
        }
    }

    /** Mutable form of [CapsuleConfig], used through [capsuleConfig] or [toBuilder]; ranges are checked by [build]. */
    @KuicksilverDsl
    public class Builder {
        /** Capsule types delivered in [CapsuleStream.capsules]; empty by default. */
        public var knownTypes: Set<Long> = emptySet()

        /** Longest known capsule accepted, 1..1 048 576 bytes; 65 536 by default. */
        public var maxCapsuleLength: Int = 65_536

        /** Longest DATAGRAM capsule accepted, longer ones are dropped; 1..1 048 576 bytes, 65 536 by default. */
        public var maxDatagramLength: Int = 65_536

        /** Send datagrams as DATAGRAM capsules when HTTP/3 datagrams are unsupported; true by default. */
        public var datagramFallback: Boolean = true

        /** Received capsules held before reading pauses, 1..4096; 16 by default. */
        public var receiveQueue: Int = 16

        /** Capsules waiting to be written before sending suspends, 1..4096; 32 by default. */
        public var sendQueue: Int = 32

        /** Known types whose capsule must be the stream's last; empty by default. */
        public var terminalTypes: Set<Long> = emptySet()

        /** The immutable configuration; throws [IllegalArgumentException] when a value is outside its range. */
        public fun build(): CapsuleConfig =
            CapsuleConfig(knownTypes, maxCapsuleLength, maxDatagramLength, datagramFallback, receiveQueue, sendQueue, terminalTypes)
    }

    /** A builder pre-filled with these values. */
    public fun toBuilder(): Builder =
        Builder().also {
            it.knownTypes = knownTypes
            it.maxCapsuleLength = maxCapsuleLength
            it.maxDatagramLength = maxDatagramLength
            it.datagramFallback = datagramFallback
            it.receiveQueue = receiveQueue
            it.sendQueue = sendQueue
            it.terminalTypes = terminalTypes
        }

    private companion object {
        const val MAX_LENGTH = 1_048_576
        const val MAX_QUEUE = 4096
    }
}

/** Builds a [CapsuleConfig] from the defaults. */
@ExperimentalKuicksilverApi
public inline fun capsuleConfig(block: CapsuleConfig.Builder.() -> Unit): CapsuleConfig = CapsuleConfig.Builder().apply(block).build()

/**
 * An Extended CONNECT stream speaking the Capsule Protocol (RFC 9297 section 3), from [Http3Stream.useCapsuleProtocol].
 * The stream's data is a sequence of capsules both ways; HTTP datagrams arrive and leave as QUIC DATAGRAM frames or as
 * DATAGRAM capsules. Once this object exists, [stream]'s `input`, `output` and `datagrams` belong to it: use [capsules],
 * [send], [datagrams] and the datagram senders here instead.
 *
 * [send], [sendDatagram] when it falls back to a capsule, and [close] have no deadline of their own: they wait for the
 * peer's flow-control credit, which a peer that stops reading may withhold for as long as it keeps the connection alive;
 * only a reset of the stream or a closed connection fails them. Bound them with `withTimeout` and [Http3Stream.reset]
 * the stream when it expires.
 */
@ExperimentalKuicksilverApi
public interface CapsuleStream {
    /** The underlying stream, for its id, headers, priority, [Http3Stream.reset] and [Http3Stream.stopSending]. */
    public val stream: Http3Stream

    /**
     * Capsules of [CapsuleConfig.knownTypes] from the peer, in order. One collector at a time. The flow ends normally at
     * the peer's FIN on a capsule boundary; it fails with [Http3Exception.MessageError] when the FIN cuts a capsule (RFC
     * 9297 section 3.3), a known capsule exceeds [CapsuleConfig.maxCapsuleLength], or anything follows a capsule of
     * [CapsuleConfig.terminalTypes] (which is delivered first), after the stream was reset and
     * stopped with H3_MESSAGE_ERROR; and with the stream's or connection's error when the peer reset the stream or the
     * connection closed. While nobody collects, reading pauses after [CapsuleConfig.receiveQueue] capsules, DATAGRAM
     * capsules behind them included.
     */
    public val capsules: Flow<Capsule>

    /**
     * Sends [capsule], whole and never interleaved with another; suspends while [CapsuleConfig.sendQueue] capsules wait.
     * Throws IllegalStateException after [close], and the write's error once writing failed (a reset, STOP_SENDING, a
     * closed connection). No deadline of its own: bound it with `withTimeout` and [Http3Stream.reset] the stream when it
     * expires; a capsule already queued when the caller gives up may still be written.
     */
    public suspend fun send(capsule: Capsule)

    /**
     * HTTP datagrams from the peer: QUIC DATAGRAM frames for this stream and DATAGRAM capsules, in one queue that keeps
     * the newest 32 when nobody collects. One collector at a time; it ends when the stream's receive side ended.
     */
    public val datagrams: Flow<ByteArray>

    /**
     * Sends [payload] as a QUIC DATAGRAM when HTTP/3 datagrams are available, answering as [Http3Stream.trySendDatagram].
     * When they are unsupported and [CapsuleConfig.datagramFallback] is on, it goes as a DATAGRAM capsule instead (RFC
     * 9297 section 3.5): `Sent` once queued, `QueueFull` while [CapsuleConfig.sendQueue] capsules wait. `TooLarge` is
     * returned as is, never retried as a capsule. `Closed` after [close] or once the send side is closed.
     */
    public fun trySendDatagram(payload: ByteArray): DatagramSendResult

    /**
     * [trySendDatagram] that waits for room: in the transport's queue, or in the capsule queue when falling back. Throws
     * as [Http3Stream.sendDatagram] does, and IllegalStateException after [close]. When falling back it may wait for
     * the peer's flow-control credit: bound it with `withTimeout` and [Http3Stream.reset] the stream when it expires.
     */
    public suspend fun sendDatagram(payload: ByteArray)

    /**
     * Writes the capsules still queued, then ends our side of the stream (FIN); [capsules] keeps reading the peer's
     * side. Throws the write's error if the queue could not be written. Calling it again does nothing more.
     *
     * The writing runs in the connection's scope: cancelling `close()` (a `withTimeout` that expired) stops only the
     * wait, the writer keeps draining the queue until it is done, the stream is reset or the connection closes. Bound it
     * with `withTimeout` and [Http3Stream.reset] the stream when it expires, which ends the writer.
     */
    public suspend fun close()
}
