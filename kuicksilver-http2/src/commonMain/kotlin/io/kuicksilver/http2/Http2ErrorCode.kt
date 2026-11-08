// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** The HTTP/2 error codes (RFC 9113 section 7) carried by RST_STREAM and GOAWAY frames. */
@ExperimentalKuicksilverApi
public enum class Http2ErrorCode(
    /** The 32-bit code on the wire. */
    public val code: Long,
) {
    /** The condition is not a result of an error (a graceful shutdown). */
    NO_ERROR(0x0),

    /** An unspecific protocol error was detected. */
    PROTOCOL_ERROR(0x1),

    /** An unexpected internal error. */
    INTERNAL_ERROR(0x2),

    /** The peer violated the flow-control protocol. */
    FLOW_CONTROL_ERROR(0x3),

    /** A SETTINGS frame was not acknowledged in time. */
    SETTINGS_TIMEOUT(0x4),

    /** A frame arrived after the stream was half-closed. */
    STREAM_CLOSED(0x5),

    /** A frame had an invalid size. */
    FRAME_SIZE_ERROR(0x6),

    /** The stream was refused before any application processing: the request can be retried. */
    REFUSED_STREAM(0x7),

    /** The stream is no longer needed. */
    CANCEL(0x8),

    /** The field compression context could not be maintained. */
    COMPRESSION_ERROR(0x9),

    /** A CONNECT tunnel's connection was reset or abnormally closed. */
    CONNECT_ERROR(0xa),

    /** The peer behaves in a way that might be generating excessive load. */
    ENHANCE_YOUR_CALM(0xb),

    /** The transport does not meet the minimum security requirements. */
    INADEQUATE_SECURITY(0xc),

    /** The request must be retried over HTTP/1.1. */
    HTTP_1_1_REQUIRED(0xd),
    ;

    /** Holds [of]. */
    public companion object {
        /**
         * The error code for [code]; an unknown code means [INTERNAL_ERROR] (RFC 9113 section 7: unknown codes MUST NOT
         * trigger special behavior and MAY be treated as INTERNAL_ERROR).
         */
        public fun of(code: Long): Http2ErrorCode = entries.firstOrNull { it.code == code } ?: INTERNAL_ERROR
    }
}
