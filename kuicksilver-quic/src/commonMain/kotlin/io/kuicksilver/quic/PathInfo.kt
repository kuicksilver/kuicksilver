// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * One path of a connection as the endpoint loop last saw it (docs/guide/quic.md, "Observability"): its addresses, its
 * validation state and the connection IDs on it. Read [ConnectionInfo.paths] for the current list, or hear each new one in
 * [ConnectionListener.onPathsUpdated]; an instance never changes.
 *
 * Connection IDs are linkable identifiers: an observer on the network that sees one can tie the packets carrying it to
 * one connection, which is why a migration moves to new ones (RFC 9000 section 9.5). Showing them to the application that
 * owns the connection is fine; sending them elsewhere (analytics, crash reports, a server) links the user's networks to
 * each other. The library never logs them, and [toString] leaves them out, so logging a [PathInfo] does not either.
 *
 * @property id The path's identifier, the one [ConnectionStats.currentPath] and [PathEvent] report.
 * @property localAddress The local address of the socket this path sends from; a server on a wildcard socket reports the
 *   address the client sent to where the socket tells it, else the socket's own (the wildcard).
 * @property remoteAddress The peer address this path sends to.
 * @property state The path's validation state (RFC 9000 section 8.2).
 * @property active Whether the connection sends on this path now; exactly one path of a list is.
 * @property localConnectionId Our connection ID the peer's packets on this path carry, in hex (empty for a zero-length
 *   ID): the latest one seen there; on the path the connection started on, before any 1-RTT packet, the handshake's. Null
 *   when the peer has not sent on this path yet.
 * @property localConnectionIdSequence The sequence number of [localConnectionId][PathInfo.localConnectionId] (RFC 9000 section 5.1.1), -1 when null.
 * @property remoteConnectionId The peer's connection ID our packets on this path carry, in hex (empty for a zero-length
 *   ID); null while the path has none (a new path that has not sent yet).
 * @property remoteConnectionIdSequence The sequence number of [remoteConnectionId][PathInfo.remoteConnectionId]; -1 when null, and for the handshake ID a
 *   client sends to before the server's first Initial gave its own.
 */
@ExperimentalKuicksilverApi
public class PathInfo internal constructor(
    public val id: PathId,
    public val localAddress: InetSocketAddress,
    public val remoteAddress: InetSocketAddress,
    public val state: PathState,
    public val active: Boolean,
    public val localConnectionId: String?,
    public val localConnectionIdSequence: Long,
    public val remoteConnectionId: String?,
    public val remoteConnectionIdSequence: Long,
) {
    /**
     * For logs: the path, its state, its addresses and the sequence numbers of its connection IDs, never the IDs themselves
     * (linkable identifiers).
     */
    override fun toString(): String =
        "PathInfo(#${id.value}${if (active) " active" else ""} $state $localAddress -> $remoteAddress, " +
            "cid seq local=$localConnectionIdSequence remote=$remoteConnectionIdSequence)"
}
