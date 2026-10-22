// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramSendResult
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.flow.Flow

/**
 * The bidirectional data stream of an Extended CONNECT (RFC 9220), with the HTTP datagrams bound to it (RFC 9297). Bytes
 * written to [output] travel in DATA frames; closing it sends FIN. WebSocket frames (RFC 6455) or capsules go inside.
 */
public interface Http3Stream {
    /** The QUIC id of the CONNECT request stream; HTTP datagrams carry it divided by 4 (quarter stream ID, RFC 9297 section 2.1). */
    public val streamId: Long

    /** Bytes the peer sent in DATA frames; it ends at the peer's FIN, independently of [output] (RFC 9114 section 4.4). */
    public val input: ByteReadChannel

    /** Bytes for the peer, sent as DATA frames; closing it sends FIN and leaves [input] readable. */
    public val output: ByteWriteChannel

    /** The transport scheduling of our sending on this stream (RFC 9218 urgency and incremental); changes apply at once. */
    public var priority: StreamPriority

    /** The peer's header section: the CONNECT request's fields on the server, the 2xx response's fields on the client (RFC 9220 section 3). */
    public val headers: Http3Headers

    /**
     * HTTP datagrams received for this stream (newest 32 kept when nobody collects). The flow ends once [input]'s side of
     * the stream closed (the peer's FIN or reset, or our STOP_SENDING): datagrams arriving after that are dropped (RFC 9297
     * section 2.1); those received before are still delivered.
     */
    public val datagrams: Flow<ByteArray>

    /**
     * Sends an HTTP datagram on this stream; `Unsupported` until both sides sent `SETTINGS_H3_DATAGRAM=1` (RFC 9297 section
     * 2.1.1), `Closed` once our send side is closed — [output] closed (FIN) or failed, or [reset] — since datagrams must
     * not be sent then (RFC 9297 section 2.1).
     */
    public fun trySendDatagram(payload: ByteArray): DatagramSendResult

    /**
     * [trySendDatagram] that waits for room in the transport's queue and throws on unsupported or oversized payloads, and
     * IllegalStateException once our send side is closed.
     */
    public suspend fun sendDatagram(payload: ByteArray)

    /** Aborts sending with [code] (RESET_STREAM). */
    public fun reset(code: Long)

    /** Asks the peer to stop sending with [code] (STOP_SENDING). */
    public fun stopSending(code: Long)

    /**
     * Speaks the Capsule Protocol (RFC 9297 section 3) on this stream from now on: [input], [output] and [datagrams] then
     * belong to the returned [CapsuleStream] and must not be used directly. Call it at most once per stream, before
     * reading [input] or writing [output].
     *
     * Checks RFC 9297 section 3.2 first. When the peer's message breaks it (a `content-length`, `content-type` or
     * `transfer-encoding` field, or a 204, 205 or 206 response), the stream is reset and stopped with H3_MESSAGE_ERROR and
     * [Http3Exception.MessageError] is thrown; when our own message does, IllegalStateException is thrown and the stream
     * is left as it was.
     *
     * Implementations outside this library (test fakes) need not override it: the default throws
     * UnsupportedOperationException.
     *
     * @throws IllegalStateException when called a second time, or when our own message breaks section 3.2.
     */
    @ExperimentalKuicksilverApi
    public fun useCapsuleProtocol(config: CapsuleConfig = CapsuleConfig()): CapsuleStream =
        throw UnsupportedOperationException("this Http3Stream does not implement the Capsule Protocol")
}
