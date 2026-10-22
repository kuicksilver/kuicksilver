// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.utils.io.ByteReadChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.Deferred

/**
 * A client request (RFC 9114 section 4.1), built with [http3Request] (or [Builder]). [authority] and [path] become the
 * pseudo-headers; [headers] must not contain pseudo-headers or connection-specific fields. `request` refuses with
 * IllegalArgumentException what the peer would treat as malformed (RFC 9114 sections 4.2, 4.3.1): a [method] that is not
 * a token, a [path] that does not start with `/` (or is `*` for OPTIONS), userinfo (`user@`) in [authority], a `host`
 * field differing from [authority], `te` other than `trailers`, invalid field names or values. A null [body] sends HEADERS
 * with FIN; otherwise the channel is copied into DATA frames until it closes, then [trailers] (if any) are sent.
 */
public class Http3Request private constructor(
    b: Builder,
) {
    /** The `:method` pseudo-header (`GET`, `POST`, ...); case-sensitive (RFC 9110 section 9.1). */
    public val method: String = b.method

    /** The `:scheme` pseudo-header; not sent for a classic CONNECT (RFC 9114 section 4.4). */
    public val scheme: String = b.scheme

    /** The `:authority` pseudo-header (`host[:port]`); null sends none, which `https` requests may only do with a `host` field. */
    public val authority: String? = b.authority

    /** The `:path` pseudo-header (path and query, `/` at least); ignored for a classic CONNECT (RFC 9114 section 4.4). */
    public val path: String? = b.path

    /** The request fields: lowercase names, no pseudo-headers, no connection-specific fields (RFC 9114 section 4.2). */
    public val headers: Http3Headers = b.headers

    /** The request content, read until the channel closes; a channel that closes with an error fails the request. */
    public val body: ByteReadChannel? = b.body

    /**
     * Called once after [body] ended; the fields it returns are sent as trailers, null sends none. It runs on the
     * dispatcher of the coroutine that called `request` (not the connection's), so it may suspend or block briefly.
     */
    public val trailers: (suspend () -> Http3Headers?)? = b.trailers

    /**
     * Sent as the `priority` field (RFC 9218 section 5) when not the default u=3, i=false, and used for our own
     * scheduling of the request stream. Without it a `priority` field among [headers] is sent as given and schedules the
     * stream too; without either a CONNECT (a tunnel) is scheduled incremental (sections 10.1, 11), any other request with
     * the defaults.
     */
    public val priority: StreamPriority? = b.priority

    /** `:protocol` of an Extended CONNECT (RFC 9220); set by `Http3Connection.connect`. */
    public val protocol: String? = b.protocol

    /**
     * Called for each interim (1xx) response before the final one, 103 Early Hints included. It runs on the dispatcher of
     * the coroutine that called `request` (not the connection's); the final response waits for it to return.
     */
    public val onInformational: (suspend (status: Int, headers: Http3Headers) -> Unit)? = b.onInformational

    /**
     * Send in 0-RTT on a connection from `Http3Endpoint.connectEarly` whose handshake is not complete yet; honoured only for a
     * safe method (GET, HEAD, OPTIONS) without a body, every other request waits for the handshake. The request may be
     * replayed by an attacker (RFC 8446 section 8); a `425 Too Early` answer is repeated once after the handshake (RFC 8470).
     */
    @property:ExperimentalKuicksilverApi
    public val allowEarlyData: Boolean

    init {
        @OptIn(ExperimentalKuicksilverApi::class)
        allowEarlyData = b.allowEarlyData
    }

    /** A builder pre-filled with this request's values. */
    @OptIn(ExperimentalKuicksilverApi::class)
    public fun toBuilder(): Builder =
        Builder(method, authority, path).also {
            it.scheme = scheme
            it.headers = headers
            it.body = body
            it.trailers = trailers
            it.priority = priority
            it.protocol = protocol
            it.onInformational = onInformational
            it.allowEarlyData = allowEarlyData
        }

    /**
     * Builds an [Http3Request]: [method], [authority] and [path] as the pseudo-headers, everything else optional; see the
     * properties of [Http3Request] for what each setting means. New options arrive as new properties here, so code that
     * builds requests keeps compiling and linking.
     */
    public class Builder(
        /** See [Http3Request.method]. */
        public var method: String,
        /** See [Http3Request.authority]. */
        public var authority: String?,
        /** See [Http3Request.path]. */
        public var path: String?,
    ) {
        /** Default `https`; see [Http3Request.scheme]. */
        public var scheme: String = "https"

        /** Default [Http3Headers.Empty]; see [Http3Request.headers]. */
        public var headers: Http3Headers = Http3Headers.Empty

        /** Default null (no content); see [Http3Request.body]. */
        public var body: ByteReadChannel? = null

        /** Default null (no trailers); see [Http3Request.trailers]. */
        public var trailers: (suspend () -> Http3Headers?)? = null

        /** Default null (u=3, i=false); see [Http3Request.priority]. */
        public var priority: StreamPriority? = null

        /** Default null; see [Http3Request.protocol]. */
        public var protocol: String? = null

        /** Default null; see [Http3Request.onInformational]. */
        public var onInformational: (suspend (status: Int, headers: Http3Headers) -> Unit)? = null

        /** Default false; see [Http3Request.allowEarlyData]. */
        @ExperimentalKuicksilverApi
        public var allowEarlyData: Boolean = false

        /** The request. */
        public fun build(): Http3Request = Http3Request(this)
    }
}

/** An [Http3Request] for [method] on [authority] and [path], with the other settings from [block]. */
public inline fun http3Request(
    method: String,
    authority: String?,
    path: String?,
    block: Http3Request.Builder.() -> Unit = {},
): Http3Request = Http3Request.Builder(method, authority, path).apply(block).build()

/** The final response to an [Http3Request]. Reading [body] to the end completes [trailers] (null without trailers). */
public interface Http3Response {
    /** The QUIC id of the request stream that carries this exchange. */
    public val streamId: Long

    /** The final `:status`, 200..599 (interim responses went to [Http3Request.onInformational]). */
    public val status: Int

    /** The validated response fields, pseudo-headers excluded (RFC 9114 section 4.2). */
    public val headers: Http3Headers

    /**
     * The response content from DATA frames; it ends at the server's FIN (and trailers, if any). A body cut short — a reset,
     * a lost connection, a failed request — fails every read with its cause ([Http3Exception] or the connection's
     * [io.kuicksilver.quic.QuicException.ConnectionLost]) and is never `isClosedForRead`, so it cannot pass for complete.
     */
    public val body: ByteReadChannel

    /** Completes once [body] was read to the end: the trailers, or null when the server sent none. */
    public val trailers: Deferred<Http3Headers?>

    /** Sends a new priority signal for this request (PRIORITY_UPDATE, RFC 9218 section 7) and applies it to our own sending. */
    public suspend fun updatePriority(priority: StreamPriority)

    /** Abandons the response: STOP_SENDING (and RESET_STREAM if the request body is still being sent) with [code]. */
    public fun cancel(code: Long = Http3ErrorCode.REQUEST_CANCELLED)
}
