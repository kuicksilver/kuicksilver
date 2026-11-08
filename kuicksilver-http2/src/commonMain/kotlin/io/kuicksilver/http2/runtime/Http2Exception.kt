// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import kotlinx.io.IOException

/**
 * Why an HTTP/2 exchange failed (RFC 9113). A call over HTTP/2 that fails surfaces one of these, or the transport's own
 * error (a TLS failure, a socket timeout). [notProcessed] is true only when the protocol proves the server did not
 * process the request (a stream above a GOAWAY's last stream identifier, REFUSED_STREAM, a request that never left this
 * client; RFC 9113 section 8.7): only such a request is safe to send again, whatever its method.
 */
@ExperimentalKuicksilverApi
public sealed class Http2Exception(
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause) {
    /** The server did not process the request: it may be retried on another connection (RFC 9113 section 8.7). */
    public abstract val notProcessed: Boolean

    /** The stream was reset with [code][Http2Exception.StreamReset.code] (RST_STREAM, or a GOAWAY that excluded it); [byPeer][Http2Exception.StreamReset.byPeer] when the server did it. */
    public class StreamReset internal constructor(
        /** The stream identifier. */
        public val streamId: Int,
        /** The error code (RFC 9113 section 7). */
        public val code: Http2ErrorCode,
        /** The server reset the stream, rather than this client after a protocol error. */
        public val byPeer: Boolean,
        override val notProcessed: Boolean,
        message: String,
    ) : Http2Exception(message)

    /**
     * The connection ended before the exchange did: a GOAWAY with an error, a connection error, a PING that went
     * unanswered, or the transport closed or failed ([cause][Http2Exception.ConnectionClosed.cause]).
     */
    public class ConnectionClosed internal constructor(
        /** The GOAWAY error code, when the connection ended with one. */
        public val code: Http2ErrorCode?,
        /** The server ended the connection. */
        public val byPeer: Boolean,
        override val notProcessed: Boolean,
        message: String,
        cause: Throwable? = null,
    ) : Http2Exception(message, cause)

    /**
     * The response was malformed (RFC 9113 section 8.1.1: an invalid or missing pseudo-header field, a connection-specific
     * field, a content-length that does not match the DATA frames): the stream was reset with PROTOCOL_ERROR and the
     * response is not used.
     */
    public class MalformedMessage internal constructor(
        message: String,
    ) : Http2Exception(message) {
        override val notProcessed: Boolean get() = false
    }

    /** The response's field section was larger than this client's SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 section 8.2). */
    public class FieldSectionTooLarge internal constructor(
        message: String,
    ) : Http2Exception(message) {
        override val notProcessed: Boolean get() = false
    }
}
