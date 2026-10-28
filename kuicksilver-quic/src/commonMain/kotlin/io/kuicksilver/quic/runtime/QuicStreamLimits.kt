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
}
