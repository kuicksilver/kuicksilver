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
import io.kuicksilver.http2.message.H2Messages
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ReceiveChannel
import kotlin.time.Duration
import kotlin.time.TimeSource

/** Monotonic nanoseconds since the first call. */
private fun monotonicNanos(): () -> Long {
    val start = TimeSource.Monotonic.markNow()
    return { start.elapsedNow().inWholeNanoseconds }
}

private fun Duration.nanosOrMax(): Long = if (isInfinite()) Long.MAX_VALUE else inWholeNanoseconds.coerceAtLeast(1)

/**
 * The client side of one HTTP/2 connection over a byte stream the engine set up (TCP and TLS with ALPN `h2`; RFC 9113
 * section 3.2). For the engines only; its contract may change in any release.
 */
@InternalKuicksilverApi
public class H2ClientConnection private constructor(
    internal val rt: H2Runtime,
) {
    /** The peer's SETTINGS_MAX_CONCURRENT_STREAMS (unlimited until it says otherwise). */
    public val peerMaxConcurrentStreams: Long get() = rt.peerMaxConcurrentStreams

    /** Streams reserved ([tryReserve]) and not released yet. */
    public val reservedStreams: Int get() = rt.reservedStreams

    /** Not ending, no GOAWAY received, transport alive: a new stream may be opened. */
    public val isUsable: Boolean get() = rt.usable

    /** Ended: nothing more is sent or received. */
    public val isClosed: Boolean get() = rt.closed.isCompleted

    /** The error code of the server's GOAWAY, once one arrived (HTTP_1_1_REQUIRED asks for HTTP/1.1, RFC 9113 section 7). */
    public val goAwayCode: Http2ErrorCode? get() = rt.goAwayCode

    /** Why the connection ended, when it did. */
    public val closeCause: Throwable? get() = rt.closeCause

    /** When the last reserved stream was released, on the connection's monotonic clock (milliseconds). */
    public val idleSinceMillis: Long get() = rt.idleSince / 1_000_000

    /** The connection's monotonic clock, in milliseconds. */
    public fun nowMillis(): Long = rt.clock() / 1_000_000

    /** Suspends until the connection ended and its transport was closed. */
    public suspend fun awaitClosed() {
        rt.closed.await()
    }

    /** Takes a stream slot within the peer's limit; false when the connection is full or not usable. */
    public fun tryReserve(): Boolean = rt.tryReserve()

    /** Gives back a slot of [tryReserve] that was not used for a stream. */
    public fun unreserve(): Unit = rt.unreserve()

    /**
     * Opens a request stream on a slot of [tryReserve]: the control data (RFC 9113 section 8.3.1) and the regular
     * [fields] (lowercase, no connection-specific fields), checked as the server would check them
     * (IllegalArgumentException otherwise). [endStream]: there is no content. [head]: a HEAD request, whose response has no
     * content (RFC 9110 section 9.3.2). Throws [Http2Exception] with `notProcessed` when this connection can take no new
     * stream; the slot is used up either way, and comes back with [H2ClientStream.release] or here on a failure.
     */
    public fun open(
        method: String,
        scheme: String,
        authority: String,
        path: String,
        fields: List<Pair<String, String>>,
        endStream: Boolean,
    ): H2ClientStream {
        val all = H2Messages.buildRequest(method, scheme, authority, path, fields)
        try {
            H2Messages.requireValidRequest(all)
            return H2ClientStream(rt, rt.open(all, endStream, headRequest = method == "HEAD"))
        } catch (e: Throwable) {
            rt.unreserve()
            throw e
        }
    }

    /** Sends GOAWAY (NO_ERROR) and takes no new streams; the connection closes once its streams are done. */
    public fun shutdown(): Unit = rt.shutdown()

    /** Closes the connection now; running streams fail with [cause]. */
    public fun abort(cause: Throwable): Unit = rt.abort(cause)

    public companion object {
        /**
         * Starts the connection on [input] and [output] (the client preface and SETTINGS go out at once) and returns once
         * the server's SETTINGS arrived (its preface, RFC 9113 section 3.4); the caller bounds that wait (the engine's
         * connect timeout), and a cancelled or failed start closes the transport. [scope] owns the connection's
         * coroutines; [closeTransport] closes the socket under the channels; [onChange] hears that capacity or usability
         * changed (from any thread, without suspending). [pingInterval]: a PING that often, and the connection ends when
         * one is still unanswered at the next; [Duration.INFINITE] for none. [clock] gives monotonic nanoseconds.
         */
        public suspend fun start(
            input: ByteReadChannel,
            output: ByteWriteChannel,
            settings: Http2Settings,
            scope: CoroutineScope,
            pingInterval: Duration,
            closeTransport: () -> Unit,
            onChange: () -> Unit = {},
            clock: () -> Long = monotonicNanos(),
        ): H2ClientConnection {
            val rt = H2Runtime(Role.CLIENT, settings, input, output, scope, clock, pingInterval.nanosOrMax(), closeTransport, onChange)
            rt.start()
            try {
                rt.prefaceReceived.await()
            } catch (e: Throwable) {
                rt.abort(e as? CancellationException ?: e)
                throw e
            }
            return H2ClientConnection(rt)
        }
    }
}

/** One request stream of an [H2ClientConnection]. */
@InternalKuicksilverApi
public class H2ClientStream internal constructor(
    private val rt: H2Runtime,
    private val s: StreamRt,
) {
    /** The stream identifier. */
    public val id: Int get() = s.id

    /** The final response head; interim (1xx) responses are skipped. Throws [Http2Exception] when the stream fails first. */
    public suspend fun response(): H2ResponseHead = s.head.await()

    /** The response content; reading it credits the peer (flow control follows the application's reading). */
    public val body: ByteReadChannel get() = s.body

    /** The trailer fields, once the body was read to its end; null when there were none. */
    public val trailers: List<Pair<String, String>>? get() = rt.lock.withLock { s.trailers }

    /** Waits at most [millis] for the server to answer anything (100 Continue, another interim or the final response). */
    public suspend fun awaitAnswer(millis: Long): Unit = rt.awaitAnswer(s, millis)

    /** Whether the final response head arrived. */
    public val hasResponse: Boolean get() = s.head.isCompleted

    /**
     * Sends [source] as the request content and ends the stream, within the server's flow-control windows; a wait for
     * window longer than [stallMillis] (null: none) fails the stream with [stallError]'s exception. Returns quietly when
     * the server stopped the request after a complete response (RFC 9113 section 8.1).
     */
    public suspend fun sendBody(
        source: ByteReadChannel,
        stallMillis: Long?,
        stallError: () -> Throwable,
    ): Unit = rt.sendBody(s, source, stallMillis, stallError)

    /** Resets the stream with CANCEL (the application gave up on it). */
    public fun cancel() {
        rt.reset(s, Http2ErrorCode.CANCEL)
    }

    /**
     * The call is over: a stream not finished both ways is reset with CANCEL, the connection forgets it and its slot comes
     * back. Every opened stream must be released once.
     */
    public fun release(): Unit = rt.release(s)
}

/**
 * The server side of one HTTP/2 connection: requests arrive on [requests]. Minimal (no flood policy beyond the core's,
 * no Ktor pipeline): the engine's tests use it as an HTTP/2 peer.
 */
@InternalKuicksilverApi
public class H2ServerConnection private constructor(
    private val requests0: Channel<H2ServerStream>,
) {
    internal lateinit var rt: H2Runtime

    /** Requests as their heads arrive, validated (RFC 9113 section 8.3.1); a malformed one is reset, never delivered. */
    public val requests: ReceiveChannel<H2ServerStream> get() = requests0

    /** Sends GOAWAY (NO_ERROR, graceful: first the largest stream identifier, then the last one taken). */
    public fun shutdown(): Unit = rt.shutdown()

    /** Closes the connection now. */
    public fun abort(cause: Throwable): Unit = rt.abort(cause)

    /**
     * Sends GOAWAY with [code] at once, not graceful: its last stream is the last one taken. NO_ERROR lets the streams taken
     * finish; an error code (HTTP_1_1_REQUIRED, say) ends the connection.
     */
    public fun goAway(code: Http2ErrorCode): Unit = rt.goAwayNow(code)

    /** Suspends until the connection ended. */
    public suspend fun awaitClosed() {
        rt.closed.await()
    }

    public companion object {
        /** Starts serving on [input] and [output]; see [H2ClientConnection.start] for the parameters. */
        public fun start(
            input: ByteReadChannel,
            output: ByteWriteChannel,
            settings: Http2Settings,
            scope: CoroutineScope,
            closeTransport: () -> Unit,
            clock: () -> Long = monotonicNanos(),
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
                    onRequest = { s, r -> ch.trySend(H2ServerStream(c.rt, s, r.method, r.path ?: "", r.authority, r.fields)) },
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
    private val rt: H2Runtime,
    private val s: StreamRt,
    /** `:method`. */
    public val method: String,
    /** `:path`. */
    public val path: String,
    /** `:authority` (or `host`). */
    public val authority: String?,
    /** The regular fields. */
    public val fields: List<Pair<String, String>>,
) {
    /** The stream identifier. */
    public val id: Int get() = s.id

    /** The request content. */
    public val body: ByteReadChannel get() = s.body

    /** Sends the response head; [endStream] when there is no content. */
    public fun respond(
        status: Int,
        fields: List<Pair<String, String>> = emptyList(),
        endStream: Boolean = false,
    ): Unit = rt.respond(s, status, fields, endStream)

    /** Sends [source] as the response content; ends the stream unless trailers follow ([end] false). */
    public suspend fun sendBody(
        source: ByteReadChannel,
        end: Boolean = true,
    ): Unit = rt.sendBody(s, source, null, { IllegalStateException("no stall timeout") }, end)

    /** Sends trailers, which end the stream. */
    public fun trailers(fields: List<Pair<String, String>>): Unit = rt.respondTrailers(s, fields)

    /** Resets the stream with [code]. */
    public fun reset(code: Http2ErrorCode): Unit = rt.reset(s, code)

    /** The handler is done with the stream. */
    public fun release(): Unit = rt.release(s)
}
