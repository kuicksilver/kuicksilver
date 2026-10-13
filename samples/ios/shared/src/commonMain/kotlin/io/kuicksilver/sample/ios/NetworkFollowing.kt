// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.ios

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.followDefaultNetwork
import kotlinx.coroutines.CoroutineScope

/**
 * "Follow the default network" (Wi-Fi to cellular and back without a new handshake): the library's
 * `QuicConnection.followDefaultNetwork(scope)` over `NWPathMonitor`, which also replaces a socket iOS reclaimed while the
 * app was suspended. The echo screen's toggle is enabled when this is true.
 */
const val FOLLOW_DEFAULT_NETWORK_AVAILABLE: Boolean = true

/** Starts following the default network for [connection] in [scope]; closing the result stops it. */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun followDefaultNetwork(
    connection: QuicConnection,
    scope: CoroutineScope,
): AutoCloseable = connection.followDefaultNetwork(scope)
