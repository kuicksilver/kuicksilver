// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress

/** An accepted socket's peer is numeric text here (inet_ntop): parsed, so the accept loop never calls getaddrinfo. */
internal actual fun peerAddressBytes(remote: InetSocketAddress): ByteArray? = parseIpLiteral(remote.hostname)
