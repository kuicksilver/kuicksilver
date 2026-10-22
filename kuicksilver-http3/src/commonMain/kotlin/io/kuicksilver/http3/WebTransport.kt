// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.runtime.ServerRequestImpl
import io.kuicksilver.http3.webtransport.webTransport
import kotlinx.io.IOException

/**
 * A WebTransport session over HTTP/3 (draft-ietf-webtrans-http3-16): an Extended CONNECT stream that groups
 * WebTransport streams and datagrams. One session per connection: there is no WebTransport flow control, and without it
 * a client keeps to one session and a server refuses a second with H3_REQUEST_REJECTED (section 5.1). The session ends
 * when its CONNECT stream ended in both directions; streams of an ended session are rejected.
 */
@ExperimentalKuicksilverApi
public interface WebTransportSession {
    /** The session's id: the QUIC stream id of its Extended CONNECT, which every WebTransport stream and datagram names. */
    public val sessionId: Long

    /** The peer's header section: the CONNECT request's fields on the server (`origin` among them), the 2xx response's on the client. */
    public val headers: Http3Headers

    /** The application protocol the server chose from the client's offer (`WT-Protocol`, section 3.3), or null when none was. */
    public val protocol: String?
}

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
 * [Http3Exception.Settings] is thrown.
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
