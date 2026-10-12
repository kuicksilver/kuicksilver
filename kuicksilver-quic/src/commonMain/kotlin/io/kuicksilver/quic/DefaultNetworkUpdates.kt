// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.callbackFlow

/**
 * A platform's default-network callback as a [NetworkMigrator] source: [register] installs `onAvailable`/`onLost` and returns
 * the unregistration, run when collection ends. `onAvailable(n)` makes `n` the default; `onLost(n)` reports null only when `n`
 * is still the default (a new default often arrives before the old network is lost). The callbacks must come one at a time
 * (Android delivers them on one handler thread); nothing is dropped, so the migrator sees each change in order.
 */
internal fun <N : Any> defaultNetworkUpdates(register: (onAvailable: (N) -> Unit, onLost: (N) -> Unit) -> () -> Unit): Flow<N?> =
    callbackFlow {
        var current: N? = null
        val unregister =
            register(
                { n ->
                    current = n
                    trySend(n)
                },
                { n ->
                    if (n == current) {
                        current = null
                        trySend(null)
                    }
                },
            )
        awaitClose { unregister() }
    }.buffer(Channel.UNLIMITED)
