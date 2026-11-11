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
import kotlinx.coroutines.CoroutineScope
import kotlin.time.Duration
import kotlin.time.TimeSource

/** Monotonic nanoseconds since the first call. */
internal fun monotonicNanos(): () -> Long {
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

    /**
     * The connection ended because the server's preface (its SETTINGS, RFC 9113 section 3.4) did not arrive within the
     * `prefaceTimeout` of [start]: the streams opened meanwhile failed with SETTINGS_TIMEOUT.
     */
    public val serverPrefaceMissed: Boolean get() = rt.peerPrefaceMissed

    /** When the last reserved stream was released, on the connection's monotonic clock (milliseconds). */
    public val idleSinceMillis: Long get() = rt.idleSince / 1_000_000

    /** The connection's monotonic clock, in milliseconds. */
    public fun nowMillis(): Long = rt.clock() / 1_000_000

    /** Suspends until the connection ended and its transport was closed. */
    public suspend fun awaitClosed() {
        rt.closed.await()
    }

    /** Milliseconds since anything arrived from the server. */
    public val receivedIdleMillis: Long get() = (rt.clock() - rt.lastReceived) / 1_000_000

    /**
     * Sends a PING and waits at most [timeoutMillis] for its acknowledgement (a connection health check); false when none
     * came or the connection ended.
     */
    public suspend fun checkHealth(timeoutMillis: Long): Boolean = rt.checkHealth(timeoutMillis)

    /** The server's preface (its SETTINGS, RFC 9113 section 3.4) arrived; until then [tryReserve] grants one stream. */
    public val serverSettingsReceived: Boolean get() = rt.peerPrefaceReceived

    /**
     * Takes a stream slot within the peer's limit; false when the connection is full or not usable. Before the server's
     * SETTINGS arrive ([serverSettingsReceived]) it grants one slot only: the server's SETTINGS_MAX_CONCURRENT_STREAMS is not
     * known yet, and streams beyond it would be refused (RFC 9113 section 5.1.2: with REFUSED_STREAM or PROTOCOL_ERROR).
     * The `onChange` callback given to `start` tells when the SETTINGS arrive.
     */
    public fun tryReserve(): Boolean = rt.tryReserve()

    /** Gives back a slot of [tryReserve] that was not used for a stream. */
    public fun unreserve(): Unit = rt.unreserve()

    /**
     * Opens a request stream on a slot of [tryReserve]: the control data (RFC 9113 section 8.3.1) and the regular
     * [fields] (lowercase, no connection-specific fields), checked as the server would check them
     * (IllegalArgumentException otherwise). [endStream]: there is no content. `head`: a HEAD request, whose response has no
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
            H2Messages.requireValidRequest(all, connectProtocolEnabled = rt.lock.withLock { rt.core.peerEnableConnectProtocol })
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
         * Starts the connection on [input] and [output] (the client preface and SETTINGS go out at once) and returns at once,
         * without waiting for the server's preface: RFC 9113 section 3.4, "To avoid unnecessary latency, clients are
         * permitted to send additional frames to the server immediately after sending the client connection preface,
         * without waiting to receive the server connection preface". Until the server's SETTINGS arrive, its settings have
         * their initial values (section 6.5.2: a 65 535-byte window, 16 384-byte frames), except that [tryReserve] grants one
         * stream only until then: the server's SETTINGS_MAX_CONCURRENT_STREAMS is not known yet (its initial value,
         * unlimited, would let a burst of requests go out that a smaller limit then refuses, section 5.1.2). When the server's preface has not arrived within [prefaceTimeout],
         * the connection ends with SETTINGS_TIMEOUT (section 6.5.3: our SETTINGS cannot be acknowledged before it) and its
         * streams fail with it ([serverPrefaceMissed]); [Duration.INFINITE] for no bound. [scope] owns the connection's
         * coroutines; [closeTransport] closes the socket under the channels; [onChange] hears that capacity or usability
         * changed (from any thread, without suspending). [pingInterval]: a PING that often, and the connection ends when
         * one is still unanswered at the next; [Duration.INFINITE] for none. [clock] gives monotonic nanoseconds.
         * [connectionErrorOf] maps a failure of [input] to the code of a connection error (RFC 9113 section 5.4.1) when the
         * transport reports something the protocol makes one, a TLS 1.2 renegotiation (section 9.2.1: PROTOCOL_ERROR): GOAWAY
         * with that code goes out on [output] and the streams fail with it; null (the default) takes the failure for a lost
         * connection. [closeTransportGracefully] ends the transport in order once the protocol is over and the last frames,
         * a GOAWAY among them, are in [output] (with TLS: those bytes, then close_notify; RFC 9113 sections 5.4.1, 6.8),
         * bounded by the caller; null uses [closeTransport], which also closes a failed or lost transport at once.
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
            connectionErrorOf: (Throwable) -> Http2ErrorCode? = { null },
            closeTransportGracefully: (() -> Unit)? = null,
            prefaceTimeout: Duration = Duration.INFINITE,
        ): H2ClientConnection {
            val rt =
                H2Runtime(
                    Role.CLIENT,
                    settings,
                    input,
                    output,
                    scope,
                    clock,
                    pingInterval.nanosOrMax(),
                    closeTransport,
                    onChange,
                    connectionErrorOf = connectionErrorOf,
                    closeTransportGracefully = closeTransportGracefully,
                )
            rt.expectPeerPrefaceWithin(prefaceTimeout.nanosOrMax())
            rt.start()
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

    /**
     * Opened before the server's preface arrived (RFC 9113 section 3.4), when its SETTINGS_MAX_CONCURRENT_STREAMS was not
     * known yet: a REFUSED_STREAM on it may only mean that the limit, once known, was below the streams opened meanwhile.
     */
    public val openedBeforeServerSettings: Boolean get() = s.beforePeerSettings

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
    public fun release() {
        rt.release(s)
    }
}
