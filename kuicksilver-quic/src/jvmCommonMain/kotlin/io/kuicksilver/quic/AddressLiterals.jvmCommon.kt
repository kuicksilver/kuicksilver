// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

// a java.net.InetSocketAddress resolved its name when it was built; an unresolved one answers null without a lookup
internal actual fun InetSocketAddress.ipBytesNoDns(): ByteArray? = resolveAddress()
