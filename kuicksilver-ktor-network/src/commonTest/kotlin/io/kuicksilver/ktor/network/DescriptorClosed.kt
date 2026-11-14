// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.sockets.ASocket

/**
 * Suspends until the descriptor of [socket], one of the engines' sockets ([connectTcp], [bindTcp], their accepted ones),
 * is closed in the system: what [ASocket.close] starts may end later, on another thread (the caller bounds the wait).
 */
internal expect suspend fun awaitDescriptorClosed(socket: ASocket)
