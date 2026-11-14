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
 * (RFC 8441) is offered when the connection starts with `enableConnectProtocol` (SETTINGS_ENABLE_CONNECT_PROTOCOL = 1);
 * otherwise a request with `:protocol` is malformed. A CONNECT answered with a 2xx is a tunnel (RFC 9113 section 8.5):
 * DATA only, both ways.
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

    /**
     * The connection ended in an error (a connection error of either side, the transport lost), not with a graceful
     * GOAWAY NO_ERROR after its streams: nothing of value is left in flight, so the engine closes it without a long linger.
     */
    public val endedInError: Boolean
        get() = (rt.closeCause as? Http2Exception.ConnectionClosed)?.let { it.code != Http2ErrorCode.NO_ERROR || it.cause != null } ?: true

    /** Bytes the connection read from the client: it stops reading when the connection ends (a flood limit included). */
    public val bytesReceived: Long get() = rt.bytesRead

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

    /**
     * Suspends until the connection ended as a protocol ([closeCause] is set): a connection error (ours or the client's
     * GOAWAY), the transport lost, or the last stream done after a GOAWAY. What is left to write may still be waiting for
     * the client to read it; [awaitClosed] returns once it went out, so the engine bounds the gap between the two.
     */
    public suspend fun awaitEnded() {
        rt.ended.await()
    }

    /**
     * The connection ended because the client broke one of the flood limits of [Http2Settings] (we sent GOAWAY
     * ENHANCE_YOUR_CALM, RFC 9113 section 5.4.1); a field block slower than `maxHeaderBlockTime` (also ENHANCE_YOUR_CALM)
     * is a slow client, not a flood, and does not count. The engine may count it against the client's address.
     */
    public val endedByFloodDefence: Boolean get() = rt.endedByFlood

    internal fun released() {
        open.update { it - 1 }
    }

    public companion object {
        /**
         * Starts serving on [input] and [output] (our SETTINGS go out at once). [scope] owns the connection's coroutines;
         * [closeTransport] closes the socket under the channels once the connection is over or lost. [clock] gives
         * monotonic nanoseconds. [ownResponseFields] go on the responses the connection makes itself (the 431 for a field
         * section above the limit): an origin server's `date` (RFC 9110 section 6.6.1), say. [enableConnectProtocol]: our
         * SETTINGS carry SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 and Extended CONNECT requests are taken (RFC 8441 section 3;
         * the request's [H2ServerStream.protocol]). [connectionErrorOf] maps a failure of [input] to the code of a connection
         * error (RFC 9113 section 5.4.1) when the transport reports something the protocol makes one, a TLS 1.2 renegotiation
         * (section 9.2.1: PROTOCOL_ERROR): GOAWAY with that code goes out on [output]; null (the default) takes the failure for
         * a lost connection.
         */
        public fun start(
            input: ByteReadChannel,
            output: ByteWriteChannel,
            settings: Http2Settings,
            scope: CoroutineScope,
            closeTransport: () -> Unit,
            clock: () -> Long = monotonicNanos(),
            ownResponseFields: () -> List<Pair<String, String>> = { emptyList() },
            enableConnectProtocol: Boolean = false,
            connectionErrorOf: (Throwable) -> Http2ErrorCode? = { null },
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
                    onRequest = { s, r, neverIndexed ->
                        val stream =
                            H2ServerStream(
                                c,
                                c.rt,
                                s,
                                r.method,
                                r.scheme,
                                r.path ?: "",
                                r.authority,
                                r.fields,
                                r.contentLength,
                                r.protocol,
                                neverIndexed,
                            )
                        c.open.update { it + 1 }
                        c.taken.update { it + 1 }
                        // a connection that ended meanwhile takes no request: the stream goes back at once. No callback
                        // can throw out of this release: onRequest runs in the dispatch, so the events it makes are left
                        // to the loop already running (afterCore), nothing waits on the new stream yet, and a server has
                        // no reservation to give back (only the clock is read, as by every core call)
                        if (ch.trySend(stream).isFailure) stream.release()
                    },
                    ownResponseFields = ownResponseFields,
                    enableConnectProtocol = enableConnectProtocol,
                    connectionErrorOf = connectionErrorOf,
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
    /**
     * `:protocol` of an Extended CONNECT (RFC 8441 section 4: `websocket`, say), as the client sent it; null for any other
     * request. Only a connection started with `enableConnectProtocol` receives one.
     */
    public val protocol: String? = null,
    /**
     * The regular fields the client sent as literals never indexed (RFC 7541 section 6.2.3), in the order received: an
     * intermediary that forwards one MUST keep that representation (section 7.1.3).
     */
    public val neverIndexed: List<Pair<String, String>> = emptyList(),
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
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    public fun invokeOnFailure(handler: (Throwable) -> Unit) {
        s.failed.invokeOnCompletion { if (it == null) handler(s.failed.getCompleted()) }
    }

    /**
     * Sends a response head: [status] and the regular [fields] (lowercase, no connection-specific fields); [endStream]
     * when there is no content. A 1xx status is an interim response (RFC 9110 section 15.2) and never ends the stream.
     * Throws [Http2Exception] when the stream already ended (the client reset it, the connection ended). Fields named in
     * [neverIndexed] are sent as literals never indexed (RFC 7541 section 6.2.3).
     */
    public fun respond(
        status: Int,
        fields: List<Pair<String, String>> = emptyList(),
        endStream: Boolean = false,
        neverIndexed: Set<String> = emptySet(),
    ): Unit = rt.respond(s, status, fields, endStream && status >= 200, neverIndexed)

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

    /**
     * Sends an ALTSVC frame (RFC 7838 section 4) on this stream: [value], an `Alt-Svc` field value of visible ASCII, applies
     * to the origin of the request. Before the response head it goes out ahead of it. Returns false, sending nothing, when
     * the stream can no longer send; IllegalArgumentException for a value that is not visible ASCII or does not fit one frame.
     */
    public fun altSvc(value: String): Boolean = rt.altSvc(s, value)

    /**
     * The stream carries a tunnel (a CONNECT, an RFC 8441 WebSocket among them): its DATA gets one frame in 16 whatever its
     * urgency (RFC 9218 section 10.1). False once the stream is gone.
     */
    public val scheduledAsTunnel: Boolean get() = rt.scheduledAsTunnel(s)

    /** The RFC 9218 urgency (0 most urgent to 7) the response's DATA is sent with; 3 until [setPriority]. */
    public val urgency: Int get() = s.urgency

    /** Whether the response's DATA shares bandwidth with the other incremental responses of its urgency; false until [setPriority]. */
    public val incremental: Boolean get() = s.incremental

    /**
     * Schedules the response's DATA with this RFC 9218 priority from now on: the more urgent responses of the connection
     * first, non-incremental ones of one urgency in stream order, incremental ones sharing (section 10); a CONNECT gets
     * a share whatever its urgency (section 10.1). The engine sets it from the request's `priority` field merged with the
     * response's (section 8). IllegalArgumentException for an [urgency] outside 0..7.
     */
    public fun setPriority(
        urgency: Int,
        incremental: Boolean,
    ): Unit = rt.setPriority(s, urgency, incremental)

    /**
     * Schedules the response by the client's RFC 9218 signal: [urgency] and [incremental] (from the request's `priority`
     * field) from now on, then each PRIORITY_UPDATE the client sends (section 7.1), also one that came before the request
     * (section 7: it overrides the field), as [policy] parses it; once the response chose its own priority
     * ([choosePriority], section 8) the updates no longer change the scheduling. The changes apply in the order the
     * frames arrived, whatever threads the calls come from.
     */
    public fun schedule(
        urgency: Int,
        incremental: Boolean,
        policy: PriorityPolicy,
    ): Unit = rt.schedule(s, urgency, incremental, policy)

    /**
     * The response's own priority (RFC 9218 section 8): [merge] turns the current priority (the client's signal so far)
     * into the response's, as urgency * 2 + (1 if incremental); later PRIORITY_UPDATEs no longer change the scheduling.
     * [merge] runs under the connection's lock and must not call into it.
     */
    public fun choosePriority(merge: (urgency: Int, incremental: Boolean) -> Int): Unit = rt.choosePriority(s, merge)

    /**
     * Sends trailers, which end the stream; fields named in [neverIndexed] as literals never indexed (RFC 7541 section
     * 6.2.3). Not on a CONNECT answered with a 2xx (IllegalStateException): only DATA go on a tunnel (RFC 9113 section 8.5).
     */
    public fun trailers(
        fields: List<Pair<String, String>>,
        neverIndexed: Set<String> = emptySet(),
    ): Unit = rt.respondTrailers(s, fields, neverIndexed)

    /** Resets the stream with [code]. */
    public fun reset(code: Http2ErrorCode): Unit = rt.reset(s, code)

    /**
     * Suspends until the client ended its side in order (its END_STREAM, after content that matched its content-length):
     * true then; false when the stream failed instead (a reset, the connection). The caller bounds the wait.
     */
    public suspend fun awaitClientEnd(): Boolean = rt.awaitRemoteEnd(s)

    /**
     * The handler is done with the stream: one not finished both ways is reset with CANCEL, except a complete response
     * whose request is still open, which the core stops with NO_ERROR after the response (RFC 9113 section 8.1); the stream
     * no longer counts toward SETTINGS_MAX_CONCURRENT_STREAMS. Every delivered stream must be released once. It may throw
     * an engine callback's exception (the first that is not a cancellation, the others suppressed under it); the stream and
     * its slot are given back all the same.
     */
    public fun release() {
        // a release that throws (an engine callback in the dispatch after its reset) was the first one: the stream was
        // given back all the same, so it no longer counts as open either
        var first = true
        try {
            first = rt.release(s)
        } finally {
            if (first) conn.released()
        }
    }
}

/** How a server engine reads the client's PRIORITY_UPDATE frames for [H2ServerStream.schedule] (RFC 9218 section 7.1). */
@InternalKuicksilverApi
public interface PriorityPolicy {
    /**
     * The Priority Field Value [value] as urgency * 2 + (1 if incremental): a complete set, a parameter left out being its
     * default (RFC 9218 section 7). Runs under the connection's lock: quick, and no calls into the connection.
     */
    public fun parse(value: String): Int

    /**
     * The client's new signal, after the scheduling followed it. [seq] grows in the order the frames arrived; calls run
     * outside the lock and may overtake each other, so one with a smaller [seq] than an earlier call is stale.
     */
    public fun signal(
        urgency: Int,
        incremental: Boolean,
        seq: Long,
    )
}
