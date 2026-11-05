// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress

/** The JVM address of an accepted socket is resolved already: its bytes, no lookup. */
internal actual fun peerAddressBytes(remote: InetSocketAddress): ByteArray? = remote.resolveAddress()
