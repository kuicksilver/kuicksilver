// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CopyableThrowable
import kotlinx.io.IOException

/**
 * Errors of the HTTP/3 layer (RFC 9114 section 8). Transport failures stay [QuicException]; [fromQuic] reads an HTTP/3 meaning out
 * of an application close or a stream reset. Cancellation is never wrapped.
 */
public sealed class Http3Exception(
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause),
    CopyableThrowable<Http3Exception> {
    /**
     * An HTTP/3 error code on the connection ([streamId] null) or on one stream; an unknown code reads as H3_NO_ERROR.
     *
     * @property h3Code the [Http3ErrorCode], already normalized: an unknown code is [Http3ErrorCode.NO_ERROR] (RFC 9114 section 9).
     * @property initiator [Initiator.Peer] when the other side sent the code, [Initiator.Local] when this endpoint closed or reset.
     * @property streamId the stream that was reset or stopped; null when the whole connection was closed.
     */
    public class Protocol(
        public val h3Code: Long,
        public val initiator: Initiator,
        public val streamId: Long?,
        message: String? = null,
    ) : Http3Exception(message ?: "${Http3ErrorCode.name(h3Code)} from $initiator${streamId?.let { " on stream $it" } ?: ""}") {
        override fun createCopy(): Protocol = Protocol(h3Code, initiator, streamId, message)
    }

    /**
     * A QPACK error code (0x200..0x202, RFC 9204 section 6).
     *
     * @property code one of [Http3ErrorCode.QPACK_DECOMPRESSION_FAILED], [Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR],
     * [Http3ErrorCode.QPACK_DECODER_STREAM_ERROR]; QPACK errors close the whole connection.
     */
    public class Qpack(
        public val code: Long,
        message: String? = null,
    ) : Http3Exception(message ?: Http3ErrorCode.name(code)) {
        override fun createCopy(): Qpack = Qpack(code, message)
    }

    /**
     * The server did not process the request (GOAWAY above its id or H3_REQUEST_REJECTED, RFC 9114 sections 4.1.1, 5.2):
     * safe to retry on a new connection.
     *
     * @property retrySafe true when the request certainly had no effect on the server, so even a non-idempotent request may be
     * sent again; every case this library raises today is retry-safe.
     */
    public class RequestNotProcessed(
        public val retrySafe: Boolean = true,
    ) : Http3Exception("request not processed by the server") {
        override fun createCopy(): RequestNotProcessed = RequestNotProcessed(retrySafe)
    }

    /** A setting the operation needs is missing or contradicts another (Extended CONNECT without the peer's consent, ...). */
    public class Settings(
        message: String,
    ) : Http3Exception(message) {
        override fun createCopy(): Settings = Settings(message ?: "")
    }

    /**
     * A malformed message (RFC 9114 section 4.1.2): the stream was reset with H3_MESSAGE_ERROR, the connection lives on.
     *
     * @property streamId the request stream that carried the malformed message.
     * @property reason which rule the message broke (a bad field name, a missing pseudo-header, ...), for logs only.
     */
    public class MessageError(
        public val streamId: Long,
        public val reason: String,
    ) : Http3Exception("malformed message on stream $streamId: $reason") {
        override fun createCopy(): MessageError = MessageError(streamId, reason)
    }

    /**
     * A field section (headers or trailers) above `maxFieldSectionSize` once decoded; the stream was stopped with H3_EXCESSIVE_LOAD.
     *
     * @property streamId the request stream whose field section was refused.
     * @property limit our [Http3Settings.maxFieldSectionSize] in bytes, counted as name + value + 32 per field (RFC 9114 section 4.2.2).
     */
    public class FieldSectionTooLarge(
        public val streamId: Long,
        public val limit: Long,
    ) : Http3Exception("field section on stream $streamId exceeds $limit bytes") {
        override fun createCopy(): FieldSectionTooLarge = FieldSectionTooLarge(streamId, limit)
    }

    /**
     * Extended CONNECT answered with a non-2xx [status] (RFC 9220 section 3).
     *
     * @property status the final `:status` the server sent, such as 501 for an unknown protocol.
     * @property headers the response fields that came with [status].
     */
    public class ConnectRejected(
        public val status: Int,
        public val headers: Http3Headers,
    ) : Http3Exception("CONNECT rejected with status $status") {
        override fun createCopy(): ConnectRejected = ConnectRejected(status, headers)
    }

    /** Conversion of transport errors into their HTTP/3 meaning. */
    public companion object {
        /** The HTTP/3 reading of a transport exception; anything without an HTTP/3 code is returned as is. */
        public fun fromQuic(e: QuicException): IOException =
            when (e) {
                is QuicException.ConnectionLost.ApplicationClosed -> byCode(e.code, e.initiator, null)
                is QuicException.StreamError.Reset -> byCode(e.code, e.initiator, e.streamId)
                is QuicException.StreamError.Stopped -> byCode(e.code, e.initiator, e.streamId)
                else -> e
            }

        private fun byCode(
            code: Long,
            initiator: Initiator,
            streamId: Long?,
        ): Http3Exception =
            when (code) {
                Http3ErrorCode.QPACK_DECOMPRESSION_FAILED,
                Http3ErrorCode.QPACK_ENCODER_STREAM_ERROR,
                Http3ErrorCode.QPACK_DECODER_STREAM_ERROR,
                -> {
                    Qpack(
                        code,
                    )
                }

                Http3ErrorCode.REQUEST_REJECTED -> {
                    RequestNotProcessed(true)
                }

                else -> {
                    Protocol(Http3ErrorCode.normalize(code), initiator, streamId)
                }
            }
    }
}
