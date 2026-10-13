// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.sample.ios

import io.kuicksilver.quic.QuicConnection
import kotlinx.coroutines.CoroutineScope

/**
 * The hook for "follow the default network" (Wi-Fi to cellular and back without a new handshake). The library API
 * (`QuicConnection.followDefaultNetwork(scope)` over `NWPathMonitor`, branch k7/ios-lib) has not landed yet; until it
 * does the toggle in the echo screen stays disabled and the manual "Rebind" button (an active migration) is the stand-in.
 *
 * TODO(k7/ios-lib): once `followDefaultNetwork` is in kuicksilver-quic's appleMain, set [FOLLOW_DEFAULT_NETWORK_AVAILABLE]
 *   to true and replace the body of [followDefaultNetwork] with `connection.followDefaultNetwork(scope); return true`.
 */
const val FOLLOW_DEFAULT_NETWORK_AVAILABLE: Boolean = false

/** Starts following the default network for [connection] in [scope]; false when the library cannot do that yet. */
@Suppress("UNUSED_PARAMETER")
internal fun followDefaultNetwork(connection: QuicConnection, scope: CoroutineScope): Boolean = false
