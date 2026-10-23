// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.http3.runtime.connect
import io.kuicksilver.http3.runtime.request
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlin.time.Duration

/** Which side of an HTTP/3 connection we are. */
public enum class Http3Role {
    /** Opens request streams and sends requests. */
    Client,

    /** Accepts requests and answers them. */
    Server,
}

/**
 * An HTTP/3 connection over a [QuicConnection] whose ALPN is `h3` (RFC 9114). Create one with [client] or [server]: both
 * open the control and QPACK streams and send SETTINGS at once, without waiting for the peer's (RFC 9114 section 6.2.1).
 * The peer's transport parameters must allow those three unidirectional streams (section 6.2); when they cannot be opened
 * within three seconds the connection closes with H3_GENERAL_PROTOCOL_ERROR.
 */
public class Http3Connection private constructor(
    internal val session: H3Session,
) : AutoCloseable {
    /** The QUIC connection this HTTP/3 connection runs on (paths, statistics, transport close). */
    public val quic: QuicConnection get() = session.quic

    /** Our side: [request] and [connect] are client-only, [acceptRequest] is server-only. */
    public val role: Http3Role get() = session.role

    /** The local settings we advertised and enforce; [peerSettings] holds the other side's. */
    public val settings: Http3Settings get() = session.settings

    /** The peer's SETTINGS once they arrived. */
    public val peerSettings: StateFlow<Http3PeerSettings?> get() = session.peerSettings

    /** The id of the last GOAWAY received (RFC 9114 section 5.2), null before any. */
    public val goAwayReceived: StateFlow<Long?> get() = session.goAwayReceived

    /** Completes when the connection is gone: an [Http3Exception] for HTTP/3 closes, the transport's exception otherwise. */
    public val closed: Deferred<Throwable> get() = session.closed

    /**
     * Client: sends [request] and returns at its final response; interim (1xx) responses go to `onInformational`. Fails
     * with [Http3Exception.RequestNotProcessed] after GOAWAY, with [Http3Exception] stream errors for this request
     * (the connection lives on), and with the connection's error once it is gone. Cancelling the call resets the stream
     * with H3_REQUEST_CANCELLED. A request the peer would have to treat as malformed (RFC 9114 sections 4.2, 4.3.1: see
     * [Http3Request]) throws IllegalArgumentException before a stream is opened; so do its trailers, which also abandon
     * the request (the stream is reset with H3_REQUEST_CANCELLED).
     */
    public suspend fun request(request: Http3Request): Http3Response {
        check(role == Http3Role.Client) { "request() is client-only" }
        return session.request(request)
    }

    /**
     * Client: Extended CONNECT (RFC 9220) with `:protocol` = [protocol] (`websocket`, ...). Waits for the peer's SETTINGS
     * and needs `SETTINGS_ENABLE_CONNECT_PROTOCOL` ([Http3Exception.Settings] otherwise); a non-2xx answer throws
     * [Http3Exception.ConnectRejected]. The method of [request] is replaced by CONNECT.
     */
    public suspend fun connect(
        request: Http3Request,
        protocol: String,
    ): Http3Stream {
        check(role == Http3Role.Client) { "connect() is client-only" }
        return session.connect(request, protocol)
    }

    /** Server: the next request; malformed requests are answered at the stream level and never returned. */
    public suspend fun acceptRequest(): Http3ServerRequest {
        check(role == Http3Role.Server) { "acceptRequest() is server-only" }
        return session.requests.receive()
    }

    /**
     * Graceful shutdown with GOAWAY (RFC 9114 section 5.2). A server announces 2^62-4, waits about two round trips, then
     * announces the first request id it will not process (those are reset with H3_REQUEST_REJECTED, which clients may
     * retry elsewhere); once its accepted requests are answered and acknowledged, the client closes the connection with
     * H3_NO_ERROR (a Kuicksilver client does once it read its responses), or the server does three seconds later. A client
     * sends GOAWAY(0) and stops issuing requests; a client that receives GOAWAY closes with H3_NO_ERROR once it is idle.
     */
    public suspend fun goAway() {
        session.goAway()
    }

    /** Closes with an HTTP/3 error code (H3_NO_ERROR by default) in CONNECTION_CLOSE 0x1d. */
    public suspend fun close(
        code: Long = Http3ErrorCode.NO_ERROR,
        reason: String = "",
    ) {
        session.close(code, reason)
    }

    override fun close() {
        session.scope.launch { session.close(Http3ErrorCode.NO_ERROR, "") }
    }

    /** Factories that start HTTP/3 on a QUIC connection. */
    public companion object {
        /**
         * Starts the client side on an established QUIC connection; returns once our SETTINGS went out. Throws
         * [Http3Exception.Protocol] (H3_GENERAL_PROTOCOL_ERROR) when the server's transport parameters do not let us open
         * the control and QPACK streams (RFC 9114 section 6.2).
         */
        public suspend fun client(
            quic: QuicConnection,
            settings: Http3Settings = Http3Settings.Default,
        ): Http3Connection = start(quic, Http3Role.Client, settings)

        /**
         * Starts the server side on an accepted QUIC connection. Returns at once, without waiting for the client: the
         * control and QPACK streams are opened in the background, and a client whose transport parameters do not allow
         * them (RFC 9114 section 6.2) has its connection closed with H3_GENERAL_PROTOCOL_ERROR (see [closed]).
         */
        public suspend fun server(
            quic: QuicConnection,
            settings: Http3Settings = Http3Settings.Default,
        ): Http3Connection = start(quic, Http3Role.Server, settings)

        /** [client] and [server]; tests shorten [criticalStreamsDeadline]. */
        internal suspend fun start(
            quic: QuicConnection,
            role: Http3Role,
            settings: Http3Settings,
            criticalStreamsDeadline: Duration = H3Session.CRITICAL_STREAMS_DEADLINE,
        ): Http3Connection {
            val s = H3Session(quic, role, settings)
            s.start(criticalStreamsDeadline)
            return Http3Connection(s)
        }
    }
}

/** A request as a server sees it (RFC 9114 section 4.1). Respond with [respond]; interim responses first with [sendInformational]. */
public interface Http3ServerRequest {
    /** The QUIC id of the request stream (a client-initiated bidirectional stream, RFC 9114 section 6.1). */
    public val streamId: Long

    /**
     * The request arrived in 0-RTT and reached the application before the handshake completed, so it may be a replay
     * (RFC 8446 section 8); only requests the server's `Http3EarlyDataPolicy.replayable` admits are handed over this way.
     */
    @ExperimentalKuicksilverApi
    public val receivedEarly: Boolean get() = false

    /** The `:method` pseudo-header, as sent (case-sensitive, RFC 9110 section 9.1). */
    public val method: String

    /** The `:scheme` pseudo-header; null only for a classic CONNECT, which carries none (RFC 9114 section 4.4). */
    public val scheme: String?

    /** The `:authority` pseudo-header (or the `host` field when it is absent), null when the request has neither. */
    public val authority: String?

    /** The `:path` pseudo-header (path and query); null only for a classic CONNECT (RFC 9114 section 4.4). */
    public val path: String?

    /** `:protocol` of an Extended CONNECT (RFC 9220), else null. */
    public val protocol: String?

    /**
     * A WebTransport session request: an Extended CONNECT with `:protocol` `webtransport-h3` (draft-15 and later) or
     * `webtransport` (older drafts, what browsers send), on a connection with `Http3Settings.webTransport`. Accept it with
     * `acceptWebTransport`, or refuse it with [respond].
     */
    @ExperimentalKuicksilverApi
    public val isWebTransport: Boolean get() = false

    /**
     * The application protocols a WebTransport client offers in `WT-Available-Protocols` (draft-ietf-webtrans-http3-16
     * section 3.3), in its order of preference; empty when it offers none or the field is not a valid list of Strings.
     */
    @ExperimentalKuicksilverApi
    public val availableProtocols: List<String> get() = emptyList()

    /** The validated request fields, pseudo-headers excluded (RFC 9114 section 4.2). */
    public val headers: Http3Headers

    /**
     * The request content from DATA frames; it ends at the client's FIN (and trailers, if any). A body cut short — the
     * client's reset, a lost connection — fails every read with its cause ([Http3Exception] or the connection's
     * [io.kuicksilver.quic.QuicException.ConnectionLost]) and is never `isClosedForRead`, so it cannot pass for complete.
     * Content still unread when the response is complete is dropped with `STOP_SENDING H3_NO_ERROR`.
     */
    public val body: ByteReadChannel

    /** Completes when the body ended: the trailers, or null. */
    public val trailers: Deferred<Http3Headers?>

    /** The client's priority signal (RFC 9218): the `priority` field, later PRIORITY_UPDATE frames. */
    public val priority: StateFlow<StreamPriority>

    /** The client's address on the path the connection uses now; it changes when the client migrates. */
    public val remoteAddress: InetSocketAddress

    /** Sends an interim response (100..199 except 101), such as 103 Early Hints. */
    public suspend fun sendInformational(
        status: Int,
        headers: Http3Headers = Http3Headers.Empty,
    )

    /**
     * Sends the final response HEADERS; the body goes through the returned writer. [priority] overrides the client's signal
     * for the scheduling of the response; without it a `priority` field in [headers] is sent and merged into the stream's
     * current priority (RFC 9218 section 8: a parameter it leaves out keeps that value). Either way later PRIORITY_UPDATEs
     * from the client no longer change the scheduling. A CONNECT without a signal from its client is scheduled
     * incremental (sections 10.1, 11), and a field such as `u=1` keeps it so.
     * A response to HEAD, and a 204 or 304, has no content (RFC 9110 sections 9.3.2, 15.3.5, 15.4.5): what is written to
     * its writer is dropped, while its `content-length` is sent as given.
     */
    public suspend fun respond(
        status: Int,
        headers: Http3Headers = Http3Headers.Empty,
        priority: StreamPriority? = null,
    ): Http3ResponseWriter

    /** Accepts an Extended CONNECT (RFC 9220): `:status 200`, then the stream carries data both ways. Unknown protocols deserve 501 instead. */
    public suspend fun acceptConnect(headers: Http3Headers = Http3Headers.Empty): Http3Stream

    /** Aborts the request stream in both directions with [code]. */
    public fun reset(code: Long)
}

/** The body of a server response: bytes written to [output] become DATA frames. */
public interface Http3ResponseWriter {
    /** The response content; the transport's flow control applies backpressure to writes. */
    public val output: ByteWriteChannel

    /**
     * Flushes [output], sends [trailers] if any, then FIN. Closing [output] without calling this ends the response without trailers.
     * Trailers above the peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` throw [Http3Exception.FieldSectionTooLarge] and reset the
     * stream with H3_INTERNAL_ERROR; trailers with a pseudo-header, a connection-specific field or `te` (RFC 9114 section
     * 4.2) throw IllegalArgumentException and reset it the same way.
     */
    public suspend fun finish(trailers: Http3Headers? = null)
}
