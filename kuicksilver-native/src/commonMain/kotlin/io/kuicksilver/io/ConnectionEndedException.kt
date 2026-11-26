// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.io

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.io.IOException

/**
 * A TCP connection under an HTTP/1.1 or HTTP/2 exchange ended, and who ended it (docs/guide/ktor.md, "Who ended the
 * connection"): the peer or the network ([PeerClosed], [PeerUnresponsive]), or this side ([LocalClose]). An app or a test
 * harness tells "the server or the network went away" from "we closed it" by type instead of by message.
 *
 * It is an [IOException], so a `catch (e: IOException)` still takes it, and its message is the one the library always
 * used. It is often the cause of another exception rather than the exception thrown: an HTTP/2 call fails with
 * `Http2Exception.ConnectionClosed` whose cause is this, so look through the causes:
 * `generateSequence(e) { it.cause }.filterIsInstance<ConnectionEndedException>().firstOrNull()`. A QUIC connection's end
 * has its own type, `QuicException.ConnectionLost`, with the initiator; a TLS failure is a `TlsException`.
 */
@ExperimentalKuicksilverApi
public sealed class ConnectionEndedException(
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause) {
    /**
     * The peer or the network ended the connection: the input reached its end (the peer's FIN, a closed socket) where
     * more was expected (`the peer closed the connection`), or, on Kotlin/Native, a write waiting for room found the
     * connection reset (`Connection reset by peer`; on the JVM and Android a reset is the platform's `SocketException`).
     */
    public class PeerClosed
        @InternalKuicksilverApi
        constructor(
            message: String,
            cause: Throwable? = null,
        ) : ConnectionEndedException(message, cause)

    /**
     * The peer stopped answering on a connection whose transport looked sound: an HTTP/2 PING went unacknowledged (the
     * `pingInterval` keepalive, `no PING acknowledgement within ... ms`, or the health check of a pooled connection, `the
     * HTTP/2 connection did not answer a health PING`), or nothing arrived within the socket timeout (`the socket timeout
     * expired`). The library ended the connection because of the peer's silence.
     */
    public class PeerUnresponsive
        @InternalKuicksilverApi
        constructor(
            message: String,
            cause: Throwable? = null,
        ) : ConnectionEndedException(message, cause)

    /**
     * This side closed the connection, nothing the peer did: the client closed it (`HttpClient.close()`, an idle or
     * expired pooled connection, `the HTTP/2 connection was closed by the client`), an orderly close dropped what was
     * still to be read (`the connection is closing`), a read came after the TLS socket was closed (`the TLS socket is
     * closed: nothing more is read`), or the TCP socket itself was closed, aborted or reset by this side while its read
     * side was open (`Socket closed`, `The connection was aborted`, on Kotlin/Native also `The connection was reset`).
     */
    public class LocalClose
        @InternalKuicksilverApi
        constructor(
            message: String,
            cause: Throwable? = null,
        ) : ConnectionEndedException(message, cause)
}
