// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.QuicConnection

/**
 * The stream limits a connection grants its peer, for the HTTP/3 layer (RFC 9218 section 7.2 checks a PRIORITY_UPDATE's
 * stream ID against them). Read without the endpoint loop's lock, like [QuicConnection.stats]: the value only grows, and
 * frames naming a stream reach the reader after the MAX_STREAMS that allowed it was queued on the loop.
 */
@InternalKuicksilverApi
public object QuicStreamLimits {
    /** How many bidirectional streams the peer may open in total (our last MAX_STREAMS); null for a connection of another kind. */
    @OptIn(ExperimentalKuicksilverApi::class)
    public fun peerBidiStreamsGranted(connection: QuicConnection): Long? =
        (connection as? ConnectionRuntime)?.core?.streams?.peerMaxStreamsGranted(bidi = true)
}
