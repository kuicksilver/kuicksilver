// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.quic.runtime.LoopGroup
import kotlin.time.Duration

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

    /**
     * As [connect] for a client with `QuicClientConfig.earlyData`: returns as soon as 0-RTT keys exist, so what the application
     * writes before the handshake completes travels in 0-RTT (RFC 9001 section 4.6). Without a usable ticket it returns at
     * handshake completion, and under `EarlyDataState.Required` it then throws [QuicException.ConnectionLost.ZeroRttRejected].
     * Early data can be replayed by an attacker: write early only what is safe to execute twice, and use
     * [QuicConnection.awaitHandshake] before the rest. A rejection is repaired by the transport (sent again in 1-RTT).
     */
    @ExperimentalKuicksilverApi
    public suspend fun connectEarly(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection = connect(remote, config)

    /** The next accepted server connection (its handshake is complete, or with `QuicServerConfig.earlyData` its 0-RTT accepted). Throws [QuicException.EndpointClosing] once closed, also while handshaken connections were still queued (they close with the endpoint). */
    public suspend fun accept(): QuicConnection

    /** The address the endpoint's socket is bound to, with the port the system picked when `bind` asked for port 0. */
    public val localAddress: InetSocketAddress

    /** [close] and then waits until every connection is closed and the socket released: a port can be rebound right after. */
    public suspend fun closeAndJoin()

    /**
     * The endpoint's counters summed over all its loops (docs/guide/quic.md, "Observability"): admission outcomes,
     * handshakes, 0-RTT, datagrams and their drops, internal failures. A cheap snapshot that any thread may take. Stable,
     * so that the stable counters (`initialsDropped` to `connectionsCreated`) can be read without an opt-in; the other
     * counters are experimental properties of [EndpointStats].
     */
    public val stats: EndpointStats

    /**
     * Graceful shutdown (docs/guide/quic.md, "Graceful shutdown"): stops taking new connections, lets the existing ones
     * finish within [grace], then closes what is left and the endpoint itself; returns once the socket is released, like
     * [closeAndJoin].
     *
     * From the call on, a new client's Initial is refused at once with a stateless CONNECTION_CLOSE carrying
     * CONNECTION_REFUSED (under the stateless rate limits), as when the accept queue is full, and `connect` throws
     * [QuicException.EndpointClosing]. Handshakes already in flight go on, and `accept()` still hands out the connections
     * that complete. Nothing is sent to the existing connections: an application protocol tells its peers to go away on
     * its own (HTTP/3 sends GOAWAY, which the Kuicksilver Ktor server does when it stops). Once every connection has
     * closed, or at the deadline, the remaining ones are closed with an application CONNECTION_CLOSE carrying [code] and
     * [reason]. A second call, or [close] meanwhile, ends the grace period at once.
     */
    @ExperimentalKuicksilverApi
    public suspend fun shutdown(
        grace: Duration,
        code: Long = 0,
        reason: String = "shutdown",
    ) {
        closeAndJoin()
    }

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

/**
 * [QuicEndpoint.close] with the application [code] and [reason] of the CONNECTION_CLOSE every live connection gets: an
 * application protocol closes with its own "no error" code (HTTP/3: H3_NO_ERROR, RFC 9114 section 5.2), where `close()`
 * sends 0. Asynchronous like `close()`.
 */
@InternalKuicksilverApi
public fun QuicEndpoint.closeWith(
    code: Long,
    reason: String,
) {
    when (this) {
        is EndpointLoop -> closeWith(code, reason)
        is LoopGroup -> closeWith(code, reason)
        else -> close()
    }
}

/**
 * Suspends until [this] stream is over at the transport level: everything we sent acknowledged (or reset), everything the
 * peer sent consumed, or the connection ended. HTTP/3's graceful close waits for it, so a response handed to QUIC is not
 * cut by the CONNECTION_CLOSE while it is still on its way (RFC 9114 section 5.2). Returns at once for streams of other
 * implementations.
 */
@InternalKuicksilverApi
public suspend fun QuicStream.awaitFinished() {
    (this as? io.kuicksilver.quic.runtime.StreamRuntime)?.done?.await()
}
