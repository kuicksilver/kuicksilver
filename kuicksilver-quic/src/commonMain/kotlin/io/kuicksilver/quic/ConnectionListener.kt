// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.tls.TlsRole

/**
 * Hears the lifecycle of every connection of an endpoint (docs/guide/quic.md, "Observability"), set with
 * `QuicEndpointConfig.listener`. Each connection reports [onOpened] first and [onClosed] last, exactly once each.
 *
 * Every callback runs on the endpoint loop that owns the connection, in the order the events happened: it must return
 * quickly and must not block or suspend (hand the work to your own coroutine when it is more than counting or logging).
 * An exception out of a callback is logged at [LogLevel.Warn] and counted, never the connection's failure.
 */
@ExperimentalKuicksilverApi
public interface ConnectionListener {
    /** A client connection was created by `connect`, or a server one was admitted from a client's Initial. */
    public fun onOpened(connection: ConnectionInfo) {}

    /** The handshake completed (RFC 9001 section 4.1.1); the peer is authenticated. */
    public fun onHandshakeCompleted(connection: ConnectionInfo) {}

    /** What became of 0-RTT on this connection (RFC 9001 section 4.6), reported once and only when 0-RTT was in play. */
    public fun onZeroRtt(
        connection: ConnectionInfo,
        outcome: ZeroRttOutcome,
    ) {}

    /** Packets now go over another path (RFC 9000 section 9): a migration of ours, or a peer that moved. */
    public fun onPathChanged(
        connection: ConnectionInfo,
        change: PathEvent.Changed,
    ) {}

    /**
     * [ConnectionInfo.paths] changed to [paths]: a connection ID rotated on a path (ours, as the peer's packets show, or the
     * peer's we send to: RFC 9000 section 5.1), a path was added, validated, failed, closed or became the active one, or a
     * peer address changed. Reported once per change the loop saw after it processed datagrams or timers, so several changes
     * at once come as one call, and not before [onOpened]. [paths] holds connection IDs, linkable identifiers: see [PathInfo]
     * before logging or sending them anywhere.
     */
    @ExperimentalKuicksilverApi
    public fun onPathsUpdated(
        connection: ConnectionInfo,
        paths: List<PathInfo>,
    ) {}

    /**
     * The connection is over. [reason] says who closed and how: [QuicException.ConnectionLost.ApplicationClosed] and
     * [QuicException.ConnectionLost.TransportClosed] carry the initiator (local or peer), the code and, for a transport
     * error, the frame type; a timeout, a Stateless Reset and the other endings have their own types.
     */
    public fun onClosed(
        connection: ConnectionInfo,
        reason: QuicException.ConnectionLost,
    ) {}
}

/** The 0-RTT outcome a [ConnectionListener] hears (RFC 9001 section 4.6.2). */
@ExperimentalKuicksilverApi
public enum class ZeroRttOutcome {
    /** Client: the server accepted our early data. Server: the client's early data is accepted and being read. */
    Accepted,

    /** Client: the server refused our early data; the transport resends it in 1-RTT, or the connection closes when it cannot. */
    Rejected,
}

/**
 * The connection a [ConnectionListener] callback is about. One instance per connection, so it can key a map from
 * [ConnectionListener.onOpened] to [ConnectionListener.onClosed]; [QuicConnection.info] returns the same one.
 *
 * @property id The connection's original destination connection ID in hex: the name of its qlog trace. It stays the same
 *   for the connection's whole life, whatever IDs its packets carry now ([paths]); the client chose it at random and it was
 *   on the wire only in the first Initial packets.
 * @property role Whether this endpoint is the connection's client or server.
 * @property connection The connection itself, for its `stats` and `paths`; inside [ConnectionListener.onOpened] of a
 *   server connection it is not yet in `accept()`'s hands.
 */
@ExperimentalKuicksilverApi
public class ConnectionInfo internal constructor(
    public val id: String,
    public val role: TlsRole,
    public val connection: QuicConnection,
    private val remote: () -> InetSocketAddress,
    private val pathsNow: () -> List<PathInfo> = { emptyList() },
    private val pathChangesNow: () -> Int = { 0 },
) {
    /** The peer's address on the path the connection sends on now; read it inside a callback (it is the loop's view). */
    public val remoteAddress: InetSocketAddress get() = remote()

    /**
     * The connection's paths with the connection IDs on each (docs/guide/quic.md, "Observability"), the active one first,
     * as the endpoint loop last published them: readable from any thread without a lock, and built only when something
     * on them changed ([ConnectionListener.onPathsUpdated]), so reading it costs nothing. After the connection closed it
     * keeps the last list. The IDs are linkable identifiers: see [PathInfo].
     */
    public val paths: List<PathInfo> get() = pathsNow()

    /**
     * How many times the connection moved to another path so far ([PathEvent.Changed], [ConnectionListener.onPathChanged]):
     * our migrations, the peer's, NAT rebindings, fallbacks after a failed validation and moves to a preferred address.
     * Readable from any thread; the difference of two readings counts the moves between them.
     */
    public val pathChanges: Int get() = pathChangesNow()

    /** For logs: the role and the connection ID. */
    override fun toString(): String = "ConnectionInfo($role $id)"
}
