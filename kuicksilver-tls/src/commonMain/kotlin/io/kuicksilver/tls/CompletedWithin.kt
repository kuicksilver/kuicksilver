// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
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
 * scope builder (`coroutineScope`, `supervisorScope`, `withContext`): a timeout that lands as the scope completes makes the
 * scope throw instead of returning. The builder may sit in a function the block calls (`RequestDns.answered` ends in a
 * `coroutineScope`, `Http3Connection.connect` in a `withContext`), where the deadline-sites check cannot see it. The rule:
 * the result is kept where it is made, inside the innermost scope (a variable or a callback written there, as
 * `RequestDns.answered`'s `onAnswered` and `Http3Connection.connect`'s `keep`), and the caller reads it after the deadline.
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

/**
 * [block]'s result within [deadline], or null when the deadline passed first or [stop] completed, before or meanwhile (a
 * closing engine that waits for its peer no more). As [completedWithin], a result that came is never dropped. A stop does
 * not cut the block before it ran: the block starts at once (undispatched) and gets [STOP_DRAIN_TURNS] more turns
 * (`yield`) after the stop, so that a block reading what is already readable (bytes in a channel, the peer's end of it)
 * finishes and its result is kept. That is a heuristic, not a bound on what is read: a block whose next bytes need more
 * than those turns (a TLS record still to decrypt on another dispatcher, a pump not scheduled yet) is cut with them unread.
 * The turns take no time of their own beyond the dispatches. A time-bounded, non-suspending drain is not done here: the
 * helper does not know the block's channel, and what matters on TCP (RFC 2525 section 2.17: unread data in the kernel at
 * the close makes it a reset) is in the kernel, which only the socket's own reader takes in, asynchronously.
 */
@InternalKuicksilverApi
public suspend fun <T : Any> completedWithinUnless(
    stop: Job,
    deadline: Duration,
    block: suspend () -> T,
): T? {
    val result = AtomicReference<T?>(null)
    coroutineScope {
        // started at once, also when [stop] completed already: what is already there (bytes in the input, the peer's end of
        // it) is still taken; on TCP a close with unread input would be a reset (RFC 2525 section 2.17)
        val work = launch(start = CoroutineStart.UNDISPATCHED) { withTimeoutOrNull(deadline) { result.store(block()) } }
        val stopper =
            launch(start = CoroutineStart.UNDISPATCHED) {
                stop.join()
                // a few more turns for the block, so it finishes reading what was readable as the stop came
                repeat(STOP_DRAIN_TURNS) {
                    if (!work.isActive) return@launch
                    kotlinx.coroutines.yield()
                }
                work.cancel()
            }
        work.join()
        stopper.cancel()
    }
    return result.load()
}

/** How many turns [completedWithinUnless] gives its block after the stop, for what is already readable. */
private const val STOP_DRAIN_TURNS = 3
