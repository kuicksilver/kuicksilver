// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.QuicConnection

/**
 * The stream limits a connection grants its peer and the peer grants it, for the HTTP/3 layer (RFC 9218 section 7.2 checks a
 * PRIORITY_UPDATE's stream ID against them, RFC 9297 section 2.1 an HTTP/3 datagram's). Read without the endpoint loop's
 * lock, like [QuicConnection.stats]: the values only grow (but for the one reset of a rejected 0-RTT, which concerns
 * streams the peer never saw), and frames naming a stream reach the reader after the MAX_STREAMS that allowed it.
 */
@InternalKuicksilverApi
public object QuicStreamLimits {
    /** How many bidirectional streams the peer may open in total (our last MAX_STREAMS); null for a connection of another kind. */
    @OptIn(ExperimentalKuicksilverApi::class)
    public fun peerBidiStreamsGranted(connection: QuicConnection): Long? =
        (connection as? ConnectionRuntime)?.core?.streams?.peerMaxStreamsGranted(bidi = true)

    /**
     * How many bidirectional streams we may open in total (the peer's last MAX_STREAMS); null for a connection of another
     * kind. RFC 9297 section 2.1 checks a received HTTP/3 datagram's stream against it on a client.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    public fun localBidiStreamsAllowed(connection: QuicConnection): Long? =
        (connection as? ConnectionRuntime)?.core?.streams?.localMaxStreamsAllowed(bidi = true)

    /**
     * Keeps the connection's receive window (its MAX_DATA credit) at least [bytes], up to `QuicConfig.maxConnectionWindow`,
     * apart from its auto-tuning; a lower value lets it shrink back for the limits advertised from then on. The HTTP/3 layer
     * sets it to what its WebTransport sessions may have in flight together, so a session nobody reads cannot hold the
     * connection's credit while the others wait. Does nothing on a connection of another kind or one that ended.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    public suspend fun setReceiveWindowFloor(
        connection: QuicConnection,
        bytes: Long,
    ) {
        (connection as? ConnectionRuntime)?.setReceiveWindowFloor(bytes)
    }

    /**
     * How many more unidirectional streams we may open now without waiting for the peer's MAX_STREAMS, once its limits are
     * known: from its transport parameters (initial_max_streams_uni), or in 0-RTT the remembered ones; a client that has
     * neither yet waits for its handshake. Null for a connection of another kind. Throws the connection's error when it ends
     * first. The HTTP/3 layer opens its control and QPACK streams without a deadline when three are allowed (RFC 9114
     * section 6.2 requires that much of every peer's transport parameters).
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    public suspend fun uniStreamsOpenable(connection: QuicConnection): Long? {
        val rt = connection as? ConnectionRuntime ?: return null
        rt.uniStreamsOpenable()?.let { return it }
        rt.awaitHandshake()
        return rt.uniStreamsOpenable()
    }

    /** The connection-level limit we last advertised (MAX_DATA), or null for a connection of another kind (a test hook). */
    @OptIn(ExperimentalKuicksilverApi::class)
    public suspend fun receiveLimit(connection: QuicConnection): Long? = (connection as? ConnectionRuntime)?.receiveLimit()
}
