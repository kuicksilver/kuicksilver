// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.quic.runtime

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Runnable
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.coroutines.CoroutineContext

/**
 * The loop's own single-threaded dispatcher ([EndpointLoop.ownDispatcher]): [inner] runs the tasks, this counts them as they
 * are queued, so the receiver on the loop's thread can tell whether work waits behind it ([BatchReceiver]) without a
 * wrapper allocated per task.
 */
internal class LoopDispatcher(
    private val inner: CoroutineDispatcher,
) : CoroutineDispatcher() {
    private val dispatched = AtomicLong(0)

    /** Tasks queued so far; it only grows. */
    fun dispatched(): Long = dispatched.load()

    override fun isDispatchNeeded(context: CoroutineContext): Boolean = inner.isDispatchNeeded(context)

    override fun dispatch(
        context: CoroutineContext,
        block: Runnable,
    ) {
        dispatched.incrementAndFetch()
        inner.dispatch(context, block)
    }

    override fun toString(): String = "LoopDispatcher($inner)"
}
