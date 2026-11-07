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
 * wrapper allocated per task. Tasks of a coroutine whose context holds [Batched] (a stream reader's hop and its wake-ups for
 * new data, the timer coroutine) are not counted: they run at the receiver's regular yields.
 *
 * A task is counted once it is in [inner]'s queue, not before: one the receiver counted when it yields is ahead of the
 * receiver in the queue and has run when the yield returns; one queued but not counted yet is counted later and costs the
 * receiver one yield for nothing, never a task left waiting.
 */
internal class LoopDispatcher(
    private val inner: CoroutineDispatcher,
) : CoroutineDispatcher() {
    private val dispatched = AtomicLong(0)

    /** Tasks queued so far, [Batched] ones excepted; it only grows. */
    fun dispatched(): Long = dispatched.load()

    override fun isDispatchNeeded(context: CoroutineContext): Boolean = inner.isDispatchNeeded(context)

    override fun dispatch(
        context: CoroutineContext,
        block: Runnable,
    ) {
        inner.dispatch(context, block)
        if (context[Batched] == null) dispatched.incrementAndFetch()
    }

    override fun toString(): String = "LoopDispatcher($inner)"

    /**
     * Marks a coroutine whose tasks wait for the receiver's regular yield (every 16 datagrams or 1 ms, [BatchReceiver]) instead
     * of running before its next batch. A stream reader's hop (`StreamInput`): run at once, a reader under a paced sender was
     * handed back to its own thread for every batch of a few datagrams (the JVM client took a third more CPU per GB from quinn's
     * server); now it takes several batches per hand-off, as before. The timer coroutine: the receiver yields when a timer is due.
     */
    object Batched : CoroutineContext.Element, CoroutineContext.Key<Batched> {
        override val key: CoroutineContext.Key<*> get() = this
    }
}
