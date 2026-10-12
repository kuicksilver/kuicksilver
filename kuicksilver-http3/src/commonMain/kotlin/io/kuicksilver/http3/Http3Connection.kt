// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.http3.runtime.H3Session
import io.kuicksilver.http3.runtime.connect
import io.kuicksilver.http3.runtime.request
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

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
     * with H3_REQUEST_CANCELLED.
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
     * retry elsewhere) and closes with H3_NO_ERROR once its accepted requests are answered. A client sends GOAWAY(0) and
     * stops issuing requests.
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
        /** Starts the client side on an established QUIC connection. */
        public suspend fun client(
            quic: QuicConnection,
            settings: Http3Settings = Http3Settings.Default,
        ): Http3Connection = start(quic, Http3Role.Client, settings)

        /** Starts the server side on an accepted QUIC connection. */
        public suspend fun server(
            quic: QuicConnection,
            settings: Http3Settings = Http3Settings.Default,
        ): Http3Connection = start(quic, Http3Role.Server, settings)

        private suspend fun start(
            quic: QuicConnection,
            role: Http3Role,
            settings: Http3Settings,
        ): Http3Connection {
            val s = H3Session(quic, role, settings)
            s.start()
            return Http3Connection(s)
        }
    }
}

/** A request as a server sees it (RFC 9114 section 4.1). Respond with [respond]; interim responses first with [sendInformational]. */
public interface Http3ServerRequest {
    /** The QUIC id of the request stream (a client-initiated bidirectional stream, RFC 9114 section 6.1). */
    public val streamId: Long

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

    /** The validated request fields, pseudo-headers excluded (RFC 9114 section 4.2). */
    public val headers: Http3Headers

    /**
     * The request content from DATA frames; it ends at the client's FIN. Content still unread when the response is
     * complete is dropped with `STOP_SENDING H3_NO_ERROR`.
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

    /** Sends the final response HEADERS; the body goes through the returned writer. [priority] overrides the client's signal. */
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
     * stream with H3_INTERNAL_ERROR.
     */
    public suspend fun finish(trailers: Http3Headers? = null)
}
