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
    /**
     * Opens a connection; returns once the handshake completed. Failures are [QuicException.ConnectionLost]; cancellation is never
     * wrapped, and a cancelled call closes the connection it started. [QuicException.ConnectionLost.Internal] when 16 draws of a
     * connection ID all hit one the endpoint loop already routes (RFC 9000 section 10.3.2: an ID belongs to one connection; only
     * likely with a short `connectionIdLength` and many connections).
     */
    public suspend fun connect(
        remote: InetSocketAddress,
        config: QuicClientConfig,
    ): QuicConnection

    /**
     * As [connect] for a client with `QuicClientConfig.earlyData`: returns as soon as 0-RTT keys exist, so what the application
     * writes before the handshake completes travels in 0-RTT (RFC 9001 section 4.6). Without a usable ticket it returns at
     * handshake completion, and under `EarlyDataState.Required` it then throws [QuicException.ConnectionLost.ZeroRttRejected].
     * Early data can be replayed by an attacker: write early only what is safe to execute twice, and use
     * [QuicConnection.awaitHandshake] before the rest. When the server rejects 0-RTT, every stream opened before the handshake
     * completed is reset (RFC 9001 section 4.6.2: the client "MUST reset the state of all streams") and fails with
     * [QuicException.StreamError.EarlyDataRejected]; nothing of it reached the server, and the application sends again on
     * new streams what it still wants.
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

    /**
     * Switches the server's connection IDs to another QUIC-LB configuration (draft-ietf-quic-load-balancers-21 section 3.1,
     * experimental; docs/guide/quic.md, "Behind a load balancer"); the endpoint must have been built with
     * `QuicEndpointConfig.loadBalancer`. New IDs use [config] from the return on; every live server connection gets one
     * NEW_CONNECTION_ID of it that retires its earlier IDs, which keep routing (and may be answered with a Stateless Reset)
     * until the next change. With null the endpoint issues unroutable IDs (codepoint 0b111, section 3.2): new connections
     * get one ID and `disable_active_migration`, live ones keep theirs. Deliver the configuration to the load balancers
     * first (section 3.1). The configuration is built on `Dispatchers.IO` (a nonce reservation's first store may fsync) and
     * switched to on the endpoint's loops, one update at a time; once switched, cancelling the caller does not undo it.
     * The call waits for the configuration's nonce reservation (its first `store`) and for the loop it switches on, and
     * cannot be cancelled while it does: a `QuicLbNonceReservation` that hangs, or a wedged loop, holds it and every later
     * update. In a group the switch happens on loop 0, and the other loops move their connections after the call returns
     * (in the background, without the caller waiting on any of them); a loop that does not do so within 5 s is logged at
     * `Warn` and moves them at its next receive batch.
     *
     * IllegalArgumentException for a configuration of another connection ID length, a plaintext one while a
     * `preferredAddress` is offered, or one that uses a server ID in clear that an encrypted configuration used, or the
     * other way round (section 9.7); IllegalStateException for an endpoint without `loadBalancer`; the default
     * implementation throws UnsupportedOperationException.
     */
    @ExperimentalKuicksilverApi
    public suspend fun updateLoadBalancer(config: QuicLbConfig?): Unit =
        throw UnsupportedOperationException("this QuicEndpoint has no QUIC-LB configuration")

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
 * Throws what [QuicEndpoint.updateLoadBalancer] would throw for [config], changing nothing (the Ktor engine checks every
 * listener before it changes any); UnsupportedOperationException for an endpoint of another implementation.
 */
@InternalKuicksilverApi
@ExperimentalKuicksilverApi
public suspend fun QuicEndpoint.checkLoadBalancer(config: QuicLbConfig?) {
    when (this) {
        is EndpointLoop -> if (group != null) group.checkLoadBalancer(config) else runOnLoop { core.checkLoadBalancerUpdate(config) }
        is LoopGroup -> checkLoadBalancer(config)
        else -> throw UnsupportedOperationException("this QuicEndpoint has no QUIC-LB configuration")
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

/**
 * Suspends until the peer sends STOP_SENDING for [this] stream (RFC 9000 section 19.5) and returns its error code; it does
 * not wait for a write to meet the stop. Never returns for a stream the peer does not stop, or for streams of other
 * implementations. HTTP/3 watches its critical streams with it (RFC 9114 section 6.2.1: closed "at any point").
 */
@InternalKuicksilverApi
public suspend fun QuicStream.awaitSendStopped(): Long =
    (this as? io.kuicksilver.quic.runtime.StreamRuntime)?.sendStopped?.await() ?: kotlinx.coroutines.awaitCancellation()

/**
 * Client: what the application kept with the session ticket this connection resumed for 0-RTT
 * ([rememberWithTickets] on the connection that received it), or null: no 0-RTT attempted, no ticket, nothing kept, or
 * a connection of another implementation. HTTP/3 keeps the server's SETTINGS there (RFC 9114 section 7.2.4.2).
 */
@InternalKuicksilverApi
public val QuicConnection.rememberedApplicationData: ByteArray?
    get() = (this as? io.kuicksilver.quic.runtime.ConnectionRuntime)?.core?.rememberedApplication

/**
 * Client: keeps [data] with every session ticket this connection received or receives (its latest few), for a later
 * 0-RTT connection to read as [rememberedApplicationData]. Ignored for connections of other implementations.
 */
@InternalKuicksilverApi
public suspend fun QuicConnection.rememberWithTickets(data: ByteArray) {
    val c = this as? io.kuicksilver.quic.runtime.ConnectionRuntime ?: return
    kotlinx.coroutines.withContext(c.loopDispatcher) { c.core.setApplicationRemembered(data.copyOf()) }
}

/**
 * How far beyond what its reader consumed so far [QuicStream.input] may take bytes from the transport (at least 1;
 * Long.MAX_VALUE, the default, for no limit beyond the input's 64 KiB buffer). Setting it fixes a stream offset: later
 * reads never take bytes past it unless they ask for them. Bytes taken leave the stream's flow-control window; a reader
 * that must leave data in the window until it can use it (RFC 9204 section 2.2.1: a blocked QPACK field section) sets it
 * to the end of what it is about to read. Set it from the reader, between its reads. Ignored for streams of other
 * implementations.
 */
@InternalKuicksilverApi
public var QuicStream.readAhead: Long
    get() = (this as? io.kuicksilver.quic.runtime.StreamRuntime)?.readAhead ?: Long.MAX_VALUE
    set(v) {
        require(v >= 1) { "readAhead must be at least 1, got $v" }
        (this as? io.kuicksilver.quic.runtime.StreamRuntime)?.readAhead = v
    }

/** Test hook: the bytes [QuicStream.input] took from the transport so far (the stream offset its buffer ends at); 0 for other implementations. */
@InternalKuicksilverApi
public val QuicStream.inputTakenForTest: Long
    get() = (this as? io.kuicksilver.quic.runtime.StreamRuntime)?.inputTakenForTest ?: 0

/**
 * Bytes [this] stream could still send now without waiting for the peer's MAX_STREAM_DATA or MAX_DATA (RFC 9000 section
 * 4.1): its own and the connection's credit, less what it already holds unsent (bytes still buffered in
 * [QuicStream.output] are not counted). HTTP/3 sizes its QPACK encoder instructions by it (RFC 9204 section 2.1.3).
 * [Long.MAX_VALUE] for streams of other implementations.
 */
@InternalKuicksilverApi
public suspend fun QuicStream.sendCredit(): Long = (this as? io.kuicksilver.quic.runtime.StreamRuntime)?.sendCredit() ?: Long.MAX_VALUE

/**
 * True once the peer's FIN and every byte before it have arrived on [this] stream (RFC 9000 section 3.2, the receiving
 * part's "Data Recvd" state, or "Data Read" once the application read them): reading [QuicStream.input] needs nothing more
 * from the network, so it ends whole even after the connection is lost. It turns true once the endpoint's loop processed
 * the packet that completed the stream and is final when [QuicConnection.closed] completes. False for a stream without a
 * receiving part, one the peer reset before its FIN, and streams of other implementations.
 */
@InternalKuicksilverApi
public val QuicStream.receivedAll: Boolean
    get() = (this as? io.kuicksilver.quic.runtime.StreamRuntime)?.receivedAll ?: false
