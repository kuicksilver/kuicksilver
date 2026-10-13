// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.shareIn

/**
 * One collection of `upstream(key)` per key, shared by every collector of `this[key]` (one default-network callback per
 * `ConnectivityManager` however many connections follow it). The upstream starts with the first collector and stops with the
 * last one; the key is then forgotten, so it is not kept alive. A late collector gets the latest value first. An upstream
 * failure ends every current collection with that exception and is not kept: the next collector starts the upstream anew.
 */
internal class SharedPerKey<K : Any, T>(
    private val upstream: (K) -> Flow<T>,
) {
    private class Entry<T>(
        val scope: CoroutineScope,
        val values: SharedFlow<Result<T>>,
    ) {
        var users = 0
    }

    private val entries = HashMap<K, Entry<T>>()

    operator fun get(key: K): Flow<T> =
        flow {
            val e =
                synchronized(entries) {
                    entries
                        .getOrPut(key) {
                            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
                            val values =
                                upstream(key)
                                    .map { Result.success(it) }
                                    .catch { emit(Result.failure(it)) }
                                    .shareIn(scope, SharingStarted.WhileSubscribed(), replay = 1)
                            Entry(scope, values)
                        }.also { it.users++ }
                }
            try {
                e.values.collect { r ->
                    r.onFailure { synchronized(entries) { if (entries[key] === e) entries.remove(key) } } // not kept for later collectors
                    emit(r.getOrThrow())
                }
            } finally {
                synchronized(entries) {
                    if (--e.users == 0) {
                        if (entries[key] === e) entries.remove(key)
                        e.scope.cancel()
                    }
                }
            }
        }
}
