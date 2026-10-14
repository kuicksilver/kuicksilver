// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.utils.io.ByteReadChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.Deferred

/**
 * A client request (RFC 9114 section 4.1). [authority] and [path] become the pseudo-headers; [headers] must not contain
 * pseudo-headers or connection-specific fields. `request` refuses with IllegalArgumentException what the peer would
 * treat as malformed (RFC 9114 sections 4.2, 4.3.1): a [method] that is not a token, a [path] that does not start with
 * `/` (or is `*` for OPTIONS), userinfo (`user@`) in [authority], a `host` field differing from [authority], `te` other
 * than `trailers`, invalid field names or values. A null [body] sends HEADERS with FIN; otherwise the channel is copied
 * into DATA frames until it closes, then [trailers] (if any) are sent.
 */
public class Http3Request(
    /** The `:method` pseudo-header (`GET`, `POST`, ...); case-sensitive (RFC 9110 section 9.1). */
    public val method: String,
    /** The `:scheme` pseudo-header; not sent for a classic CONNECT (RFC 9114 section 4.4). */
    public val scheme: String = "https",
    /** The `:authority` pseudo-header (`host[:port]`); null sends none, which `https` requests may only do with a `host` field. */
    public val authority: String?,
    /** The `:path` pseudo-header (path and query, `/` at least); ignored for a classic CONNECT (RFC 9114 section 4.4). */
    public val path: String?,
    /** The request fields: lowercase names, no pseudo-headers, no connection-specific fields (RFC 9114 section 4.2). */
    public val headers: Http3Headers = Http3Headers.Empty,
    /** The request content, read until the channel closes; a channel that closes with an error fails the request. */
    public val body: ByteReadChannel? = null,
    /**
     * Called once after [body] ended; the fields it returns are sent as trailers, null sends none. It runs on the
     * dispatcher of the coroutine that called `request` (not the connection's), so it may suspend or block briefly.
     */
    public val trailers: (suspend () -> Http3Headers?)? = null,
    /** Sent as the `priority` field (RFC 9218 section 5) when not the default u=3, i=false. */
    public val priority: StreamPriority? = null,
    /** `:protocol` of an Extended CONNECT (RFC 9220); set by `Http3Connection.connect`. */
    public val protocol: String? = null,
    /**
     * Called for each interim (1xx) response before the final one, 103 Early Hints included. It runs on the dispatcher of
     * the coroutine that called `request` (not the connection's); the final response waits for it to return.
     */
    public val onInformational: (suspend (status: Int, headers: Http3Headers) -> Unit)? = null,
    /**
     * Send in 0-RTT on a connection from `Http3Endpoint.connectEarly` whose handshake is not complete yet; honoured only for a
     * safe method (GET, HEAD, OPTIONS) without a body, every other request waits for the handshake. The request may be
     * replayed by an attacker (RFC 8446 section 8); a `425 Too Early` answer is repeated once after the handshake (RFC 8470).
     */
    @property:ExperimentalKuicksilverApi
    public val allowEarlyData: Boolean = false,
)

/** The final response to an [Http3Request]. Reading [body] to the end completes [trailers] (null without trailers). */
public interface Http3Response {
    /** The QUIC id of the request stream that carries this exchange. */
    public val streamId: Long

    /** The final `:status`, 200..599 (interim responses went to [Http3Request.onInformational]). */
    public val status: Int

    /** The validated response fields, pseudo-headers excluded (RFC 9114 section 4.2). */
    public val headers: Http3Headers

    /** The response content from DATA frames; it ends at the server's FIN and fails with the stream's error after a reset. */
    public val body: ByteReadChannel

    /** Completes once [body] was read to the end: the trailers, or null when the server sent none. */
    public val trailers: Deferred<Http3Headers?>

    /** Sends a new priority signal for this request (PRIORITY_UPDATE, RFC 9218 section 7) and applies it to our own sending. */
    public suspend fun updatePriority(priority: StreamPriority)

    /** Abandons the response: STOP_SENDING (and RESET_STREAM if the request body is still being sent) with [code]. */
    public fun cancel(code: Long = Http3ErrorCode.REQUEST_CANCELLED)
}
