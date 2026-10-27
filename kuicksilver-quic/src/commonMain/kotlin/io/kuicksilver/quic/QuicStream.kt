// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

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
     * [QuicException.StreamError.Reset] and unsent data is dropped. Returns at once; the loop sends the frame.
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

    /** Server: data of this stream arrived in 0-RTT packets, before the handshake completed; it may be a replay (RFC 9846 section 8). */
    @ExperimentalKuicksilverApi
    public val receivedEarly: Boolean get() = false
}
