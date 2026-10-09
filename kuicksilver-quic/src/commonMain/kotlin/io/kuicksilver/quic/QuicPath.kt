// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.flow.StateFlow

/**
 * One network path of a [QuicConnection] (RFC 9000 section 9): a local socket and the peer address it talks to.
 * The first path is the one the connection was established on; a client adds more with [QuicConnection.addPath],
 * validates them with [probe] and moves the connection with [switchTo]. A server only observes paths its client moves to.
 */
public interface QuicPath {
    /** The path's identifier within the connection, the one [ConnectionStats.currentPath] reports. */
    public val id: PathId

    /** The local address of the socket this path sends from. */
    public val localAddress: InetSocketAddress

    /** The peer address this path sends to. */
    public val remoteAddress: InetSocketAddress

    /** Unknown, Validating, Validated, Failed or Closed (RFC 9000 section 8.2). */
    public val state: StateFlow<PathState>

    /** Sends a PATH_CHALLENGE and suspends until the path is validated (true) or gives up after max(3 x PTO, 6 x initial RTT) (false). */
    public suspend fun probe(): Boolean

    /** Moves the connection to this validated path; the previous path stays as a fallback until it is closed. IllegalStateException when the path is not validated. */
    public suspend fun switchTo()

    /** Forgets the path and closes its socket (asynchronously, on the endpoint loop). The active path cannot be closed: IllegalStateException. */
    public fun close()
}

/** What happens to a connection's paths; collect [QuicConnection.pathEvents]. */
public sealed interface PathEvent {
    /** [path] answered our PATH_CHALLENGE (RFC 9000 section 8.2.3), or the handshake validated it. */
    public class Validated(
        public val path: QuicPath,
    ) : PathEvent

    /** [path] never answered within the validation timeout, max(3 x PTO, 6 x initial RTT) (RFC 9000 section 8.2.4). */
    public class Failed(
        public val path: QuicPath,
    ) : PathEvent

    /**
     * The connection now sends on [new] instead of [old]: our own migration, the peer's, a NAT rebinding or a fallback after a failed
     * validation, as [reason] says (RFC 9000 section 9).
     */
    public class Changed(
        public val old: QuicPath,
        public val new: QuicPath,
        public val reason: PathChangeReason,
    ) : PathEvent
}

/** Nested into [PathEvent] before 0.1.0 (K6 D1); this alias goes away in 0.2.0. */
@Deprecated("Nested as PathEvent.Changed", ReplaceWith("PathEvent.Changed"))
public typealias PathChanged = PathEvent.Changed
