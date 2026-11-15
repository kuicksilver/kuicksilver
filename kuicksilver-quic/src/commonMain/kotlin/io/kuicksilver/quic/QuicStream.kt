// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.StateFlow

/**
 * A QUIC stream as two ktor-io channels. Closing [output] sends FIN; closing it with a cause sends
 * RESET_STREAM; cancelling [input] sends STOP_SENDING. A peer reset or stop surfaces as [QuicException.StreamError]
 * in the channel's cause chain; a lost connection surfaces as its [QuicException.ConnectionLost]. A unidirectional
 * stream has one half (see [isUnidirectional]): [input] of our own one and [output] of the peer's throw IllegalStateException.
 */
public interface QuicStream {
    /**
     * The stream id (RFC 9000 section 2.1): bit 0x1 tells who opened the stream, bit 0x2 whether it is unidirectional; see
     * [isUnidirectional] and [isClientInitiated].
     */
    public val id: Long

    /**
     * The bytes the peer sends, in order. Only its FIN, with every byte before it read, ends the channel (`isClosedForRead`,
     * -1 from `readAvailable`, `closedCause` null). Any other end fails every read with its cause instead of reporting an end,
     * and leaves the channel not `isClosedForRead`: [QuicException.StreamError.Reset] when the peer resets the stream,
     * [QuicException.StreamError.Stopped] after our [stopSending], [QuicException.ConnectionLost] once the connection is gone
     * (a close by either side, an idle timeout, a stateless reset). A lost connection takes nothing the peer sent before it:
     * the bytes already received are still read, up to the FIN when it came too (then the stream ends cleanly, as above),
     * and only then do reads fail with the [QuicException.ConnectionLost]. A reset still fails the reads at once (RFC 9000
     * section 3.2: the data it abandons may be discarded). IllegalStateException on our own unidirectional stream.
     */
    public val input: ByteReadChannel

    /**
     * The bytes we send: `flushAndClose()` sends FIN, closing with a cause sends RESET_STREAM with `QuicConfig.defaultStreamErrorCode`, and
     * a peer's STOP_SENDING fails writes with [QuicException.StreamError.Stopped] as the cause. IllegalStateException on the peer's
     * unidirectional stream.
     */
    public val output: ByteWriteChannel

    /**
     * Send priority among the connection's streams (RFC 9218 at the transport): the priority the stream was opened with, or
     * [StreamPriority.Default] for a stream the peer opened, until assigned; an assignment reaches the endpoint loop asynchronously.
     */
    public var priority: StreamPriority

    /**
     * Abandons sending with RESET_STREAM carrying application error [code] (RFC 9000 section 19.4): [output] fails with
     * [QuicException.StreamError.Reset] and unsent data is dropped. Returns at once; the loop sends the frame. Once all
     * data and the FIN were acknowledged there is nothing to abandon (section 3.1: a reset leaves only the "Ready",
     * "Send", or "Data Sent" states), and no frame goes.
     */
    public fun reset(code: Long)

    /**
     * Abandons sending like [reset], but with RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset): the first
     * [reliableSize] bytes are still delivered to the peer's application, however many packets are lost, and the peer sees
     * the reset after them. Bytes count only once they were flushed to the stream; a larger [reliableSize] is cut to them.
     * Needs `QuicConfig.resetStreamAt` on both sides; otherwise it is [reset] (RESET_STREAM), and the prefix may be lost. Our
     * own setting is required too, not only the peer's: the frame then goes out only on connections where the application
     * opted in to the extension (the same switch makes us accept it), so RFC 9000 behaviour stays the default. The frame
     * waits until every reliable byte was sent once, so its final size stays within the peer's flow control: on a stream
     * starved of credit the reset reaches the peer only once credit arrives, and a later [reset] cuts that short.
     * Implementations outside this library need not override it: the default is [reset].
     */
    @ExperimentalKuicksilverApi
    public fun resetAt(
        code: Long,
        reliableSize: Long,
    ): Unit = reset(code)

    /**
     * Asks the peer to stop sending with STOP_SENDING carrying application error [code] (RFC 9000 section 19.5): [input] fails with
     * [QuicException.StreamError.Stopped] and buffered data is dropped. Returns at once.
     */
    public fun stopSending(code: Long)

    /**
     * The final size of our sending half (RFC 9000 section 4.5): the flow-control credit it consumed, as the peer counts it.
     * Completes once the size can no longer change: once the RESET_STREAM of [reset] or of the answer to the peer's
     * STOP_SENDING is queued, or the RESET_STREAM_AT of [resetAt] (which waits for its reliable bytes to go out once), with
     * the size that frame carries; after FIN, once the FIN was first sent, with every byte written (a later reset carries
     * the same size). A stream opened in 0-RTT completes only once the server accepted it. Fails with the connection's
     * [QuicException.ConnectionLost] when the connection ends first, with [QuicException.StreamError.EarlyDataRejected]
     * when a rejected 0-RTT dropped the stream, and at once with IllegalStateException on the peer's unidirectional stream.
     * The same Deferred is handed to every caller: await it, never cancel it, or the others see the cancellation too. Null
     * from implementations outside this library that do not track it.
     */
    @ExperimentalKuicksilverApi
    public val sentFinalSize: Deferred<Long>? get() = null

    /**
     * The final size of the peer's sending half (RFC 9000 section 4.5), completed as soon as its FIN, RESET_STREAM or
     * RESET_STREAM_AT made it known, whether or not the bytes were read (also after [stopSending]): what a protocol that
     * counts the peer's data across streams needs for a reset stream (draft-ietf-webtrans-http3-16 section 5.4). The size
     * counts every byte of the stream, an application's own header included. Fails like [sentFinalSize] when the
     * connection ends first or a rejected 0-RTT dropped the stream, and at once with IllegalStateException on our own
     * unidirectional stream. Shared like [sentFinalSize]: never cancel it. Null from implementations outside this library
     * that do not track it.
     */
    @ExperimentalKuicksilverApi
    public val receivedFinalSize: Deferred<Long>? get() = null

    /**
     * The highest offset of the peer's half received so far, whether read or not and in order or not (RFC 9000 section 4.1:
     * flow control counts it), then its final size once a reset or FIN told it. It only grows; 0 on our own unidirectional
     * stream. What a protocol that limits the peer's data across streams checks, also for bytes nobody reads yet
     * (draft-ietf-webtrans-http3-16 section 5.6.4). Null from implementations outside this library that do not track it.
     */
    @ExperimentalKuicksilverApi
    public val receivedOffset: StateFlow<Long>? get() = null

    /** Server: data of this stream arrived in 0-RTT packets, before the handshake completed; it may be a replay (RFC 9846 section 8). */
    @ExperimentalKuicksilverApi
    public val receivedEarly: Boolean get() = false
}
