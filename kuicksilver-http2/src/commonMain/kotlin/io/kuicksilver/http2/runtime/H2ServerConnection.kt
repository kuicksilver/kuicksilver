// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.core.Role
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/**
 * The server side of one HTTP/2 connection over a byte stream the engine set up (TCP and TLS with ALPN `h2`; RFC 9113
 * section 3.2): requests arrive on [requests], validated (section 8.3.1; a malformed one is reset with PROTOCOL_ERROR and
 * never delivered, one whose field section is above our SETTINGS_MAX_HEADER_LIST_SIZE is answered 431). Extended CONNECT
 * (RFC 8441) is not offered: SETTINGS_ENABLE_CONNECT_PROTOCOL is never sent, so a request with `:protocol` is malformed.
 * The flood limits are the core's ([Http2Settings]). For the engines only; its contract may change in any release.
 */
@InternalKuicksilverApi
public class H2ServerConnection private constructor(
    private val requests0: Channel<H2ServerStream>,
) {
    internal lateinit var rt: H2Runtime
    private val open = MutableStateFlow(0)

    /** Requests as their heads arrive; closed when the connection ends. Every one must be [H2ServerStream.release]d. */
    public val requests: ReceiveChannel<H2ServerStream> get() = requests0

    /** Requests delivered on [requests] and not released yet: 0 means the connection is idle. */
    public val openRequests: StateFlow<Int> get() = open

    private val taken = MutableStateFlow(0L)

    /**
     * Requests delivered so far, counting up: unlike [openRequests], a request that came and went between two looks still
     * shows (a StateFlow conflates 0, 1, 0 into 0).
     */
    public val requestsTaken: StateFlow<Long> get() = taken

    /** Ended: nothing more is sent or received. */
    public val isClosed: Boolean get() = rt.closed.isCompleted

    /** Why the connection ended, when it did. */
    public val closeCause: Throwable? get() = rt.closeCause

    /**
     * Suspends until the client's connection preface (the fixed octets and its first SETTINGS, section 3.4) has arrived;
     * throws when the connection ended first. The caller bounds the wait (the engine's request-head deadline).
     */
    public suspend fun awaitPreface() {
        rt.prefaceReceived.await()
    }

    /**
     * Sends GOAWAY (NO_ERROR) in two steps (section 6.8): first with the largest stream identifier and a PING, then, when
     * the PING is answered (or after `settingsAckTimeout`), with the last stream taken. The streams taken finish, and the
     * connection closes once they are done.
     */
    public fun shutdown(): Unit = rt.shutdown()

    /** Closes the connection now (GOAWAY INTERNAL_ERROR when it can still be written); running streams fail with [cause]. */
    public fun abort(cause: Throwable): Unit = rt.abort(cause)

    /**
     * Sends GOAWAY with [code] at once, not graceful: its last stream is the last one taken. NO_ERROR lets the streams taken
     * finish; an error code (HTTP_1_1_REQUIRED, say) ends the connection.
     */
    public fun goAway(code: Http2ErrorCode): Unit = rt.goAwayNow(code)

    /** Suspends until the connection ended and its transport was closed. */
    public suspend fun awaitClosed() {
        rt.closed.await()
    }

    internal fun released() {
        open.update { it - 1 }
    }

    public companion object {
        /**
         * Starts serving on [input] and [output] (our SETTINGS go out at once). [scope] owns the connection's coroutines;
         * [closeTransport] closes the socket under the channels once the connection is over or lost. [clock] gives
         * monotonic nanoseconds. [ownResponseFields] go on the responses the connection makes itself (the 431 for a field
         * section above the limit): an origin server's `date` (RFC 9110 section 6.6.1), say.
         */
        public fun start(
            input: ByteReadChannel,
            output: ByteWriteChannel,
            settings: Http2Settings,
            scope: CoroutineScope,
            closeTransport: () -> Unit,
            clock: () -> Long = monotonicNanos(),
            ownResponseFields: () -> List<Pair<String, String>> = { emptyList() },
        ): H2ServerConnection {
            val ch = Channel<H2ServerStream>(Channel.UNLIMITED) // bounded by our SETTINGS_MAX_CONCURRENT_STREAMS in the core
            val c = H2ServerConnection(ch)
            val rt =
                H2Runtime(
                    Role.SERVER,
                    settings,
                    input,
                    output,
                    scope,
                    clock,
                    Long.MAX_VALUE,
                    closeTransport = {
                        ch.close()
                        closeTransport()
                    },
                    onChange = {},
                    onRequest = { s, r ->
                        val stream = H2ServerStream(c, c.rt, s, r.method, r.scheme, r.path ?: "", r.authority, r.fields, r.contentLength)
                        c.open.update { it + 1 }
                        c.taken.update { it + 1 }
                        // a connection that ended meanwhile takes no request: the stream goes back at once
                        if (ch.trySend(stream).isFailure) stream.release()
                    },
                    ownResponseFields = ownResponseFields,
                )
            c.rt = rt
            rt.start()
            return c
        }
    }
}

/** One request a [H2ServerConnection] received. */
@InternalKuicksilverApi
public class H2ServerStream internal constructor(
    private val conn: H2ServerConnection,
    private val rt: H2Runtime,
    private val s: StreamRt,
    /** `:method`. */
    public val method: String,
    /** `:scheme` (none for a CONNECT, RFC 9113 section 8.5). */
    public val scheme: String?,
    /** `:path` (empty for a CONNECT). */
    public val path: String,
    /** `:authority`, or the `host` field when the request has no `:authority`. */
    public val authority: String?,
    /** The regular fields, lowercase names, in the order received (repeated `content-length` values collapsed). */
    public val fields: List<Pair<String, String>>,
    /** The request's `content-length`, -1 without one; the content is checked against it (RFC 9113 section 8.1.1). */
    public val contentLength: Long,
) {
    /** The stream identifier. */
    public val id: Int get() = s.id

    /**
     * The request content; reading it credits the client (flow control follows the handler's reading). Only the client's
     * END_STREAM, after content that matched its content-length, ends it; a reset or a malformed request fails it.
     */
    public val body: ByteReadChannel get() = s.body

    /** The stream failed ([invokeOnFailure] has run or runs now): nothing more can be sent on it. */
    public val failed: Boolean get() = s.failed.isCompleted

    /**
     * Runs [handler] with the stream's failure once the stream fails: the client reset it (RST_STREAM), the request was
     * malformed after its head (content that does not match content-length), or the connection ended. At once when it
     * failed already. Not run for a stream that completed both ways.
     */
    public fun invokeOnFailure(handler: (Throwable) -> Unit) {
        s.failed.invokeOnCompletion { if (it == null) handler(s.failed.getCompleted()) }
    }

    /**
     * Sends a response head: [status] and the regular [fields] (lowercase, no connection-specific fields); [endStream]
     * when there is no content. A 1xx status is an interim response (RFC 9110 section 15.2) and never ends the stream.
     * Throws [Http2Exception] when the stream already ended (the client reset it, the connection ended).
     */
    public fun respond(
        status: Int,
        fields: List<Pair<String, String>> = emptyList(),
        endStream: Boolean = false,
    ): Unit = rt.respond(s, status, fields, endStream && status >= 200)

    /**
     * Sends [source] as the response content within the client's flow-control windows, and ends the stream unless trailers
     * follow ([end] false). A wait for window longer than [stallMillis] (null: none) fails the stream with [stallError]'s
     * exception and resets it with CANCEL. Returns quietly when the client stopped the stream after a complete response.
     */
    public suspend fun sendBody(
        source: ByteReadChannel,
        end: Boolean = true,
        stallMillis: Long? = null,
        stallError: () -> Throwable = { kotlinx.io.IOException("the client took no content for $stallMillis ms") },
    ): Unit = rt.sendBody(s, source, stallMillis, stallError, end)

    /** Sends trailers, which end the stream. */
    public fun trailers(fields: List<Pair<String, String>>): Unit = rt.respondTrailers(s, fields)

    /** Resets the stream with [code]. */
    public fun reset(code: Http2ErrorCode): Unit = rt.reset(s, code)

    /**
     * The handler is done with the stream: one not finished both ways is reset with CANCEL, except a complete response
     * whose request is still open, which the core stops with NO_ERROR after the response (RFC 9113 section 8.1); the stream
     * no longer counts toward SETTINGS_MAX_CONCURRENT_STREAMS. Every delivered stream must be released once.
     */
    public fun release() {
        if (rt.release(s)) conn.released()
    }
}
