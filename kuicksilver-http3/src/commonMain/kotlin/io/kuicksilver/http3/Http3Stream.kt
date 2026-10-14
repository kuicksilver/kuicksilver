// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
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
}
