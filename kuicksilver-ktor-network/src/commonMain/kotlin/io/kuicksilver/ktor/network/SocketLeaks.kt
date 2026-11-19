// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.sockets.ASocket
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.LeakRegistry

/**
 * The leak sentinel's record of this socket (docs/process.md, "The leak sentinel") as [kind], until its context completes:
 * closed, with its read and write loops ended. Off in production: one read, no handler.
 */
internal fun ASocket.trackLeak(kind: String) {
    val id = LeakRegistry.open(kind)
    if (id != 0L) socketContext.invokeOnCompletion { LeakRegistry.close(id) }
}
