// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

/**
 * The endpoint's accepted connections, in order, until it closes: the flow completes normally on
 * [QuicException.EndpointClosing]. Collect it once; each [QuicEndpoint.accept] hands a connection to one collector.
 */
public fun QuicEndpoint.incomingConnections(): Flow<QuicConnection> =
    flow {
        while (true) {
            val connection =
                try {
                    accept()
                } catch (e: QuicException.EndpointClosing) {
                    return@flow
                }
            emit(connection)
        }
    }

/**
 * Streams the peer opened, in id order, until the connection ends for any reason; the flow then completes normally and
 * the reason is in [QuicConnection.closed]. Cancelling the collector does not touch the connection.
 */
public fun QuicConnection.incomingStreams(): Flow<QuicStream> =
    flow {
        while (true) {
            val stream =
                try {
                    acceptStream()
                } catch (e: QuicException.ConnectionLost) {
                    return@flow
                }
            emit(stream)
        }
    }

/** True for a unidirectional stream (RFC 9000 section 2.1, bit 0x2 of the id): ours has only `output`, the peer's only `input`. */
public val QuicStream.isUnidirectional: Boolean get() = id and 0x2L != 0L

/** True when the client opened the stream (RFC 9000 section 2.1, bit 0x1 of the id is 0). */
public val QuicStream.isClientInitiated: Boolean get() = id and 0x1L == 0L

/**
 * The path the connection sends on now (`stats.currentPath`; after a migration that is the new path, not `paths.first()`),
 * or null when no live path is left. A snapshot: the loop may switch paths right after.
 */
public val QuicConnection.activePath: QuicPath? get() {
    val current = stats.currentPath
    return paths.firstOrNull { it.id == current }
}
