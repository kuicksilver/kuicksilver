// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * Moves this client connection to a fresh socket: the recovery after [PathEvent.SocketLost] (iOS took the socket while the app
 * was suspended) or whenever the socket under the active path should be replaced. Opens [DatagramIo.open] at [local] (the
 * wildcard address of the peer's family by default, any port; [prefer] picks the transport), [migrates][QuicConnection.migrate]
 * there (RFC 9000 section 9: the new path is validated before the connection sends on it) and closes the path it left, with
 * its socket unless that is the endpoint's own.
 *
 * Throws what [QuicConnection.migrate] throws: IllegalStateException when the new path does not validate (the new socket is
 * closed, the connection stays where it was), the [QuicException.ConnectionLost] of a connection that ended, and for a server
 * connection or a peer that sent `disable_active_migration` the same failures as [QuicConnection.addPath].
 */
@ExperimentalKuicksilverApi
public suspend fun QuicConnection.rebind(
    local: InetSocketAddress? = null,
    prefer: IoPreference = IoPreference.Accelerated,
): PathEvent.Changed {
    val changed = migrate(DatagramIo.open(local ?: wildcardLocal(), prefer))
    try {
        changed.old.close()
    } catch (_: IllegalStateException) {
        // the peer's own move made it active again: it stays
    }
    return changed
}

/** The wildcard address (any port) of the family of the peer this connection talks to: where a new socket for it binds. */
internal fun QuicConnection.wildcardLocal(): InetSocketAddress =
    InetSocketAddress(
        if (paths
                .firstOrNull()
                ?.remoteAddress
                ?.resolveAddress()
                ?.size == 16
        ) {
            "::"
        } else {
            "0.0.0.0"
        },
        0,
    )
