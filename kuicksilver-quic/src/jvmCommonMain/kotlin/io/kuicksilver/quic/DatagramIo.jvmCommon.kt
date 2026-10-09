// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress

internal actual suspend fun openPortableDatagramIo(local: InetSocketAddress): DatagramIo = NioDatagramIo.open(local)
