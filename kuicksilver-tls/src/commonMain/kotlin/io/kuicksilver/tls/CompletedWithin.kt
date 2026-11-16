// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicReference
import kotlin.time.Duration

/**
 * [block]'s result, or null when [deadline] ran out first. Unlike `withTimeoutOrNull` a block that returned is never
 * dropped: the timeout fires on another thread ("the timeout event is asynchronous with respect to the code running in
 * the block"), and when it lands after the block returned but before the timeout's scope completed, `withTimeoutOrNull`
 * gives null for a result that already happened: bytes consumed, an item dequeued, a stream opened, a capsule written.
 *
 * What the block did before a cancellation that stopped it is not covered: a block whose steps hand over ownership must
 * keep what it took when it is cancelled half-way (see `HandOffQueue` in kuicksilver-http3). Nor is a block that ends in a
 * `coroutineScope` (or another scope builder): a timeout that lands as the scope completes makes the scope throw instead
 * of returning, so such a block sets its result inside the scope, as the work ends (a variable written there).
 */
@InternalKuicksilverApi
public suspend fun <T : Any> completedWithin(
    deadline: Duration,
    block: suspend () -> T,
): T? {
    val result = AtomicReference<T?>(null)
    withTimeoutOrNull(deadline) { result.store(block()) } // no suspension point between the return and the store
    return result.load()
}
