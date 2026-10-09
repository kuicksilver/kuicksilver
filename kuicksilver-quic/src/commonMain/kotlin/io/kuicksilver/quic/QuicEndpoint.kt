// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.quic.runtime.LoopGroup

/**
 * A bound UDP endpoint hosting QUIC connections: one endpoint loop, or `QuicEndpointConfig.loops` of them on one port (docs/architecture.md, `kuicksilver-quic`).
 *
 * `close()` closes every connection with CONNECTION_CLOSE (code 0) and then the socket. It is asynchronous: it returns at
 * once and the loop finishes the work, so a port reused right after may still be bound for a moment; `connect` and
 * `accept` throw [QuicException.EndpointClosing] from then on. [closeAndJoin] waits for that work.
 */
public interface QuicEndpoint : AutoCloseable {
    /** Opens a connection; returns once the handshake completed. Failures are [QuicException.ConnectionLost]; cancellation is never wrapped, and a cancelled call closes the connection it started. */
    public suspend fun connect(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection

    /** The next accepted server connection (its handshake is complete). Throws [QuicException.EndpointClosing] once closed, also while handshaken connections were still queued (they close with the endpoint). */
    public suspend fun accept(): QuicConnection

    /** The address the endpoint's socket is bound to, with the port the system picked when `bind` asked for port 0. */
    public val localAddress: InetSocketAddress

    /** [close] and then waits until every connection is closed and the socket released: a port can be rebound right after. */
    public suspend fun closeAndJoin()

    /** Holds [bind], the way to create an endpoint. */
    public companion object {
        /** Binds [local] (port 0 picks a free port) and starts the endpoint loop. */
        public suspend fun bind(
            local: InetSocketAddress,
            config: QuicEndpointConfig = QuicEndpointConfig.Default,
        ): QuicEndpoint =
            if (config.loops >
                1
            ) {
                LoopGroup.bind(local, config)
            } else {
                EndpointLoop.bind(local, config)
            }
    }
}
