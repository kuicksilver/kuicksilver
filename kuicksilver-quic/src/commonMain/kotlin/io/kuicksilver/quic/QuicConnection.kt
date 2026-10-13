// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.Certificate
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

/** One QUIC connection as the application sees it (docs/guide/quic.md). */
public interface QuicConnection : AutoCloseable {
    /**
     * Opens a bidirectional stream with [priority]; suspends while the peer's stream limit is reached (RFC 9000 section 4.6) and throws
     * the connection's [QuicException.ConnectionLost] once it is gone. The peer learns of the stream with its first data.
     */
    public suspend fun openBidi(priority: StreamPriority = StreamPriority.Default): QuicStream

    /** Opens a unidirectional stream (only its `output` exists), with the same waiting and failure rules as [openBidi]. */
    public suspend fun openUni(priority: StreamPriority = StreamPriority.Default): QuicStream

    /** The next stream the peer opened, in id order. */
    public suspend fun acceptStream(): QuicStream

    /** A snapshot of the connection's counters, readable from any thread; fields are read without a lock, so they need not all come from one instant. */
    public val stats: ConnectionStats

    /** The certificate chain the peer presented in the handshake; empty when it sent none (a client without client authentication). */
    public val peerCertificates: List<Certificate>

    /**
     * The application protocol both sides agreed on through ALPN (RFC 9001 section 8.1); QUIC requires one, so null only if the handshake
     * settled none.
     */
    public val negotiatedAlpn: String?

    /** The connection's paths; the first is the one it was established on (RFC 9000 section 9). */
    public val paths: List<QuicPath>

    /** Validation results and path changes, ours and the peer's (RFC 9000 section 9). A hot flow without replay: collect it before calling [migrate] or [QuicPath.probe] to see their events. */
    public val pathEvents: Flow<PathEvent>

    /**
     * Client only: a new path to the server through [io] (a second socket), unvalidated. IllegalStateException before the
     * handshake is confirmed, when the server advertised `disable_active_migration`, or beyond four paths; the socket is closed then,
     * as on any other failure or cancellation before the path took it over.
     */
    public suspend fun addPath(io: DatagramIo): QuicPath

    /**
     * Client only: [addPath] + [QuicPath.probe] + [QuicPath.switchTo]. A failed validation throws [PathValidationException] (an
     * IllegalStateException, "path validation failed"), leaves the connection where it was and closes [newIo]; its reason is
     * [PathFailureReason.NoSpareConnectionId] when the server gave no spare connection ID in time (right after the handshake the probe
     * waits for one, see [QuicPath.probe]).
     */
    public suspend fun migrate(newIo: DatagramIo): PathEvent.Changed

    /**
     * Queues a datagram (RFC 9221). Under [DatagramPolicy.Reject] it suspends while the send queue is full; under
     * DropOldest / LatestWins it never suspends, and what is buffered for the loop is bounded too (at most twice
     * `QuicConfig.datagramSendQueue`): a burst that outruns the loop loses its oldest datagrams even on an idle network, so
     * send a burst you cannot lose under Reject. Throws [QuicException.DatagramTooLarge] above [maxDatagramSize] and
     * [QuicException.DatagramUnsupported] when either side has datagrams off.
     */
    public suspend fun sendDatagram(
        data: ByteArray,
        policy: DatagramPolicy = DatagramPolicy.DropOldest,
    )

    /** [sendDatagram] without suspending: the queue is the loop's, this call only hands the copy over and never blocks. Once the connection is gone it throws the connection's [QuicException.ConnectionLost] (not [DatagramSendResult.QueueFull]: a caller retrying on that would spin). */
    public fun trySendDatagram(
        data: ByteArray,
        policy: DatagramPolicy = DatagramPolicy.DropOldest,
    ): DatagramSendResult

    /**
     * Received datagrams, newest-128 semantics: what nobody collected in time is dropped (counted in `stats.datagramsDropped`
     * beside the UDP datagrams the connection discarded unprocessed).
     * Pull-based over one queue, so two collectors split the datagrams between them. When the connection ends the flow
     * throws its [QuicException.ConnectionLost], a local `close` included ([QuicException.ConnectionLost.ApplicationClosed]).
     */
    public val datagrams: Flow<Datagram>

    /** Largest payload [sendDatagram] accepts right now; 0 while unknown or unsupported. Follows the path MTU. */
    public val maxDatagramSize: StateFlow<Int>

    /**
     * Starts a key update (RFC 9001 section 6); suspends until one is allowed: handshake confirmed, the current phase
     * acknowledged (section 6.1) and, after an earlier update, three PTOs since that acknowledgment (section 6.5).
     */
    public suspend fun keyUpdate()

    /** RFC 5705 exporter over the connection's TLS session; runs on the endpoint loop (the TLS object is not shared across threads). */
    public suspend fun exportKeyingMaterial(
        label: String,
        context: ByteArray?,
        length: Int,
    ): ByteArray

    /** Closes with an application error code; returns once the CONNECTION_CLOSE left. `close()` without arguments (from [AutoCloseable]) does the same with code 0 without waiting. */
    public suspend fun close(
        code: Long = 0,
        reason: String = "",
    )

    /** Completes when the connection is gone, with the reason every stream also sees. */
    public val closed: Deferred<QuicException.ConnectionLost>

    /** The sans-IO core behind this connection; touch it only from the endpoint loop. */
    @ExperimentalKuicksilverApi public val core: ConnectionCore

    /**
     * Whether 0-RTT was accepted (RFC 9001 section 4.6.2): null until known or when none was attempted. Client: what we sent
     * early was rejected (false) and went again in 1-RTT, or accepted (true). Server: this connection's early data was
     * accepted; it may be a replay (RFC 8446 section 8).
     */
    @ExperimentalKuicksilverApi
    public val earlyDataAccepted: Boolean? get() = null

    /**
     * Returns once the handshake completed (RFC 9001 section 4.1.1); throws the connection's [QuicException.ConnectionLost]
     * when it failed. A server connection accepted before completion (0-RTT) is authenticated only from here on: act on
     * input that is not safe to repeat only after this returns. Immediate for a connection from `connect`/`accept` without 0-RTT.
     */
    @ExperimentalKuicksilverApi
    public suspend fun awaitHandshake() {}

    /** True once the handshake completed (see [awaitHandshake]); false for a 0-RTT connection still handshaking. */
    @ExperimentalKuicksilverApi
    public val isHandshakeComplete: Boolean get() = true
}
