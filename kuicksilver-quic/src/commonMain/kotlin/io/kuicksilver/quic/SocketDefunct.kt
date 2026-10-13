// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.io.IOException

/**
 * A [DatagramIo] can no longer carry datagrams: the system took the socket away or the network under it went down, so neither
 * a retry nor waiting brings it back. iOS does this to the sockets of a suspended app (`ENOTCONN`, `EBADF`, `EPIPE` after the
 * app returns to the foreground); `ENETDOWN`, `ENETUNREACH` and `EHOSTUNREACH` on receive mean the interface went away.
 *
 * The endpoint loop does not fail the connection or the endpoint for it: it stops using the socket, reports
 * [PathEvent.SocketLost] for every path on it, and the connection waits, within its idle timeout, for a move to a new socket
 * ([QuicConnection.rebind], [QuicConnection.migrate] or a [NetworkMigrator]). A server endpoint's own socket is the
 * exception: it ends the endpoint, since its clients address that port.
 *
 * A custom [DatagramIo] throws it from `receive` or `send` for the same conditions.
 *
 * @property errno the system error number (Windows: the WSA code), 0 when there is none.
 */
@ExperimentalKuicksilverApi
public class SocketDefunctException(
    message: String,
    public val errno: Int = 0,
    cause: Throwable? = null,
) : IOException(message, cause)

/** True for the socket errors that mean "this socket is gone" (see [SocketDefunctException]); per platform, with the WSA codes everywhere. */
internal expect fun isDefunctErrno(errno: Int): Boolean

/** The WSA codes of the same conditions (ksl_udp_win.c reports these): WSAEBADF, WSAENOTSOCK, WSAENETDOWN, WSAENETUNREACH, WSAENOTCONN, WSAESHUTDOWN, WSAEHOSTUNREACH. */
internal fun isDefunctWsa(errno: Int): Boolean =
    errno == 10009 || errno == 10038 || errno in 10050..10051 || errno == 10057 || errno == 10058 || errno == 10065
