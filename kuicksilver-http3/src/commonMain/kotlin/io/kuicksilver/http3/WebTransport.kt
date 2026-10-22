// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.runtime.ServerRequestImpl
import io.kuicksilver.http3.webtransport.webTransport
import io.kuicksilver.quic.DatagramSendResult
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.StateFlow
import kotlinx.io.IOException

/**
 * A WebTransport session over HTTP/3 (draft-ietf-webtrans-http3-16): an Extended CONNECT stream that groups
 * WebTransport streams and datagrams. One session per connection: there is no WebTransport flow control, and without it
 * a client keeps to one session and a server refuses a second with H3_REQUEST_REJECTED (section 5.1).
 *
 * The session ends with [close] on either side (WT_CLOSE_SESSION with a code and a reason, then FIN), with the peer's
 * FIN on the CONNECT stream (code 0), or with a failure (a malformed capsule, a reset CONNECT stream, a lost
 * connection); [closed] says which. Its streams are then reset and stopped with WT_SESSION_GONE, opening and accepting
 * throw [WebTransportException.SessionClosed], and the connection's session slot is free once both directions of the
 * CONNECT stream ended. Application error codes, of the session and of its streams, are 0..2^32-1 (section 4.4).
 */
@ExperimentalKuicksilverApi
public interface WebTransportSession {
    /** The session's id: the QUIC stream id of its Extended CONNECT, which every WebTransport stream and datagram names. */
    public val sessionId: Long

    /** The peer's header section: the CONNECT request's fields on the server (`origin` among them), the 2xx response's on the client. */
    public val headers: Http3Headers

    /** The application protocol the server chose from the client's offer (`WT-Protocol`, section 3.3), or null when none was. */
    public val protocol: String?

    /**
     * Opens a bidirectional stream (section 4.3). Waits for the peer's QUIC stream credit (its `initial_max_streams_bidi`
     * and MAX_STREAMS), without a deadline of its own: bound it with `withTimeout`. Throws
     * [WebTransportException.SessionClosed] once the session is over.
     */
    public suspend fun openBidi(): WebTransportBidiStream

    /** Opens a unidirectional stream (section 4.2); waits for stream credit like [openBidi]. */
    public suspend fun openUni(): WebTransportSendStream

    /** The next bidirectional stream the peer opened; [WebTransportException.SessionClosed] once the session is over. */
    public suspend fun acceptBidi(): WebTransportBidiStream

    /** The next unidirectional stream the peer opened; [WebTransportException.SessionClosed] once the session is over. */
    public suspend fun acceptUni(): WebTransportReceiveStream

    /**
     * Sends an HTTP datagram of the session (section 4.5), as [Http3Stream.trySendDatagram] answers: `TooLarge` carries the
     * largest payload, the session's quarter stream ID already taken off; `Closed` once the session is over.
     */
    public fun trySendDatagram(payload: ByteArray): DatagramSendResult

    /** [trySendDatagram] that waits for room in the transport's queue; throws as [Http3Stream.sendDatagram] does. */
    public suspend fun sendDatagram(payload: ByteArray)

    /**
     * The next datagram from the peer; the newest 32 are kept while nobody receives. Throws
     * [WebTransportException.SessionClosed] once the session is over and the received ones were taken.
     */
    public suspend fun receiveDatagram(): ByteArray

    /** True once the peer asked to wind the session down: its WT_DRAIN_SESSION, or an HTTP/3 GOAWAY (section 4.7). */
    public val drainRequested: StateFlow<Boolean>

    /** Asks the peer to wind the session down (WT_DRAIN_SESSION, section 4.7); the session stays usable. */
    public suspend fun drain()

    /**
     * Closes the session (section 6): WT_CLOSE_SESSION with [code] (0..2^32-1) and [reason] (cut to 1024 bytes of UTF-8
     * at a character boundary), then FIN, then STOP_SENDING WT_SESSION_GONE on the CONNECT stream; the session's streams
     * are reset with WT_SESSION_GONE. Writing the capsule waits at most five seconds for the peer's flow-control credit,
     * after which the CONNECT stream is reset instead. Calling it on a closed session does nothing.
     */
    public suspend fun close(
        code: Long = 0,
        reason: String = "",
    )

    /** Completes when the session is over, with how it ended. */
    public val closed: Deferred<WebTransportCloseInfo>
}

/**
 * How a WebTransport session ended.
 *
 * @property code the application code of the WT_CLOSE_SESSION (ours or the peer's); 0 when the session ended without
 *   one (a FIN, or a failure).
 * @property reason the reason of the WT_CLOSE_SESSION, empty without one.
 * @property cause the failure that ended the session (an [Http3Exception], a lost connection), or null for a clean
 *   close or FIN.
 */
@ExperimentalKuicksilverApi
public class WebTransportCloseInfo(
    public val code: Long,
    public val reason: String,
    public val cause: Throwable?,
) {
    override fun equals(other: Any?): Boolean =
        other is WebTransportCloseInfo && other.code == code && other.reason == reason && other.cause == cause

    override fun hashCode(): Int = (code.hashCode() * 31 + reason.hashCode()) * 31 + (cause?.hashCode() ?: 0)

    override fun toString(): String = "WebTransportCloseInfo(code=$code, reason=$reason, cause=$cause)"
}

/**
 * The receiving side of a WebTransport stream. A reset by the peer fails [input] with
 * [WebTransportException.StreamReset].
 */
@ExperimentalKuicksilverApi
public interface WebTransportReceiveStream {
    /** The QUIC stream id. */
    public val streamId: Long

    /** The bytes the peer sends; it ends at the peer's FIN. */
    public val input: ByteReadChannel

    /** Asks the peer to stop sending with the application [code], 0..2^32-1 (STOP_SENDING); [input] then fails. */
    public fun stopSending(code: Long)
}

/** The sending side of a WebTransport stream. The peer's STOP_SENDING fails [output] with [WebTransportException.StreamStopped]. */
@ExperimentalKuicksilverApi
public interface WebTransportSendStream {
    /** The QUIC stream id. */
    public val streamId: Long

    /** Bytes for the peer; closing it sends FIN. The transport's flow control applies backpressure to writes. */
    public val output: ByteWriteChannel

    /** Abandons sending with the application [code], 0..2^32-1 (RESET_STREAM); [output] then fails. */
    public fun reset(code: Long)
}

/** A bidirectional WebTransport stream: both sides, each ending on its own. */
@ExperimentalKuicksilverApi
public interface WebTransportBidiStream :
    WebTransportReceiveStream,
    WebTransportSendStream

/** A WebTransport session failed in a way specific to WebTransport; HTTP/3 failures stay [Http3Exception]. */
@ExperimentalKuicksilverApi
public sealed class WebTransportException(
    message: String,
) : IOException(message) {
    /**
     * The server chose an application protocol the client did not offer (section 3.3); the session was closed with
     * WT_ALPN_ERROR.
     *
     * @property offered the protocols the client offered in `WT-Available-Protocols`.
     * @property selected the protocol the server's `WT-Protocol` names. A `WT-Protocol` that is no valid Structured Field
     *   String is ignored instead, as if the server chose none (section 3.3).
     */
    public class Alpn(
        public val offered: List<String>,
        public val selected: String,
    ) : WebTransportException("the server chose WebTransport protocol '$selected', not one of $offered")

    /** The peer did not answer within the deadline of a session's handshake (ten seconds per step); the CONNECT was reset. */
    public class Timeout(
        message: String,
    ) : WebTransportException(message)

    /** The session is over (closed by either side, its CONNECT stream ended, or the connection lost): see [WebTransportSession.closed]. */
    public class SessionClosed(
        message: String,
    ) : WebTransportException(message)

    /**
     * The peer reset the stream (RESET_STREAM).
     *
     * @property code the peer's application code, or null when its HTTP/3 code is outside the WebTransport range (such as
     *   WT_SESSION_GONE when the session closed).
     */
    public class StreamReset(
        public val code: Long?,
    ) : WebTransportException("WebTransport stream reset by the peer with ${code ?: "a code outside the application range"}")

    /**
     * The peer asked us to stop sending on the stream (STOP_SENDING).
     *
     * @property code the peer's application code, or null when its HTTP/3 code is outside the WebTransport range.
     */
    public class StreamStopped(
        public val code: Long?,
    ) : WebTransportException("WebTransport stream stopped by the peer with ${code ?: "a code outside the application range"}")
}

/**
 * Client: opens a WebTransport session with an Extended CONNECT to [request]'s authority and path (its method is replaced
 * by CONNECT). Needs `Http3Settings.webTransport` on this connection (IllegalStateException otherwise) and waits up to
 * ten seconds for the server's SETTINGS, which must offer WebTransport, Extended CONNECT and HTTP datagrams
 * ([Http3Exception.Settings] otherwise), then up to ten seconds for the answer to the CONNECT
 * ([WebTransportException.Timeout] otherwise; the CONNECT is reset with H3_REQUEST_CANCELLED). The draft the server
 * speaks picks the `:protocol` token: `webtransport-h3` for draft-15 and later, else `webtransport` with
 * `sec-webtransport-http3-draft02: 1`. [protocols] are offered in `WT-Available-Protocols` (printable ASCII each); a
 * `WT-Protocol` answer that names another protocol closes the session with WT_ALPN_ERROR and throws
 * [WebTransportException.Alpn], one that is no valid Structured Field String is ignored ([WebTransportSession.protocol]
 * is null). A non-2xx answer throws [Http3Exception.ConnectRejected]
 * (redirects are not followed, section 3.2). A second session while one is open throws IllegalStateException (one
 * session per connection, section 5.1).
 */
@ExperimentalKuicksilverApi
public suspend fun Http3Connection.webTransport(
    request: Http3Request,
    protocols: List<String> = emptyList(),
): WebTransportSession {
    check(role == Http3Role.Client) { "webTransport() is client-only" }
    return session.webTransport(request, protocols)
}

/**
 * Server: accepts a WebTransport session ([Http3ServerRequest.isWebTransport] must be true, IllegalStateException
 * otherwise). Waits up to ten seconds for the client's SETTINGS (section 7.1); without them, or without
 * `SETTINGS_H3_DATAGRAM=1`, the request is malformed (section 3.1): it is answered with 400 and
 * [Http3Exception.Settings] is thrown. A request with `content-length`, `content-type` or `transfer-encoding` cannot carry the session's
 * capsules (RFC 9297 section 3.2): it is answered with 400 and [Http3Exception.MessageError] is thrown.
 * Then answers 200 with [headers], `WT-Protocol` when [protocol] is set (it must be one of
 * [Http3ServerRequest.availableProtocols], IllegalArgumentException otherwise) and, for a draft-02 client, the
 * `sec-webtransport-http3-draft: draft02` field it requires. Streams the client opened for the session before this are
 * delivered to it. To refuse a session, answer with [Http3ServerRequest.respond] instead (a 4xx).
 */
@ExperimentalKuicksilverApi
public suspend fun Http3ServerRequest.acceptWebTransport(
    headers: Http3Headers = Http3Headers.Empty,
    protocol: String? = null,
): WebTransportSession {
    check(isWebTransport) { "acceptWebTransport() needs a WebTransport CONNECT on a connection with Http3Settings.webTransport" }
    val impl = this as? ServerRequestImpl ?: throw IllegalStateException("acceptWebTransport() needs a request from Http3Connection")
    return impl.acceptWebTransport(headers, protocol)
}
