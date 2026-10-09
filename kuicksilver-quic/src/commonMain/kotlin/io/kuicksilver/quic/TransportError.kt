// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

/** Transport error codes (RFC 9000 section 20.1; 0x11 from RFC 9368 section 4). */
public object TransportError {
    /** The connection closed without an error; also what `maxConnectionLifetime` sends. */
    public const val NO_ERROR: Long = 0x00L

    /** The endpoint hit an internal error and cannot continue. */
    public const val INTERNAL_ERROR: Long = 0x01L

    /** The server refuses the connection; an admission policy can answer with it ([AdmissionDecision.Close]). */
    public const val CONNECTION_REFUSED: Long = 0x02L

    /** The peer sent more data than the advertised limits allow (RFC 9000 section 4). */
    public const val FLOW_CONTROL_ERROR: Long = 0x03L

    /** The peer opened a stream beyond the advertised stream limit (RFC 9000 section 4.6). */
    public const val STREAM_LIMIT_ERROR: Long = 0x04L

    /** A frame arrived for a stream in a state that does not allow it, such as STREAM on our send-only stream. */
    public const val STREAM_STATE_ERROR: Long = 0x05L

    /** A frame changed or exceeded a stream's final size (RFC 9000 section 4.5). */
    public const val FINAL_SIZE_ERROR: Long = 0x06L

    /** A frame was badly formatted: an unknown type, a length beyond the packet, an impossible value. */
    public const val FRAME_ENCODING_ERROR: Long = 0x07L

    /** The peer's transport parameters were malformed, out of range or inconsistent (RFC 9000 section 7.4). */
    public const val TRANSPORT_PARAMETER_ERROR: Long = 0x08L

    /** The peer issued more connection IDs than our `active_connection_id_limit` allows (RFC 9000 section 5.1.1). */
    public const val CONNECTION_ID_LIMIT_ERROR: Long = 0x09L

    /** A protocol rule was broken that has no more specific code; also the close of an exhausted glitch bucket. */
    public const val PROTOCOL_VIOLATION: Long = 0x0aL

    /** A server received a Retry token it cannot accept: forged, expired or for another address (RFC 9000 section 8.1.3). */
    public const val INVALID_TOKEN: Long = 0x0bL

    /**
     * The application closed the connection; the code an Initial or Handshake copy of an application close carries (RFC 9000 section
     * 10.2.3).
     */
    public const val APPLICATION_ERROR: Long = 0x0cL

    /** The peer sent more out-of-order CRYPTO data than we buffer. */
    public const val CRYPTO_BUFFER_EXCEEDED: Long = 0x0dL

    /** A key update broke the rules of RFC 9001 section 6. */
    public const val KEY_UPDATE_ERROR: Long = 0x0eL

    /** A key reached its confidentiality or integrity limit and could not be updated in time (RFC 9001 section 6.6). */
    public const val AEAD_LIMIT_REACHED: Long = 0x0fL

    /** No path is left that can carry the connection (RFC 9000 section 9). */
    public const val NO_VIABLE_PATH: Long = 0x10L

    /** Version negotiation information was missing or contradicted the packets (RFC 9368 section 4). */
    public const val VERSION_NEGOTIATION_ERROR: Long = 0x11L

    /** CRYPTO_ERROR (0x0100-0x01ff): a TLS alert carried as a transport error code. */
    public const val CRYPTO_ERROR_BASE: Long = 0x0100L

    /** The transport error code for a TLS alert (RFC 9001 section 4.8). */
    public fun crypto(alert: Int): Long {
        require(alert in 0..255) { "alert must be 0..255" }
        return CRYPTO_ERROR_BASE + alert
    }
}
