// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel

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
     * The bytes the peer sends, in order, ending at its FIN; fails with [QuicException.StreamError.Reset] when the peer resets the stream.
     * IllegalStateException on our own unidirectional stream.
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
     * Asks the peer to stop sending with STOP_SENDING carrying application error [code] (RFC 9000 section 19.5): [input] fails with
     * [QuicException.StreamError.Stopped] and buffered data is dropped. Returns at once.
     */
    public fun stopSending(code: Long)
}
