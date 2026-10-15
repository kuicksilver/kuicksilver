// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.InterestSuspensionsMap
import io.ktor.network.selector.SelectInterest
import io.ktor.network.selector.Selectable
import io.ktor.network.selector.SelectorManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.nio.channels.Pipe
import java.nio.channels.SelectableChannel
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Registers the read end of a pipe nobody writes to on [selector] and waits for it to become readable, which it never does:
 * `ActorSelectorManager` then always has one interest pending and selects (with its 500 ms timeout) instead of waiting for
 * new interests, and every select first deregisters the keys of closed channels, which is when NIO really closes their
 * descriptors. The wait ends when the selector closes (it resumes every suspension with an error); the pipe is closed then.
 * The waiting coroutine is not a child of the selector's job: a scope that closes its selector only after its children
 * ended (the server's listener) must not wait for it.
 */
internal actual fun keepSelecting(selector: SelectorManager) {
    val pipe = selector.provider.openPipe()
    pipe.source().configureBlocking(false)
    val keeper = PipeKeeper(pipe)
    keeper.interestOp(SelectInterest.READ, true)
    CoroutineScope(selector.coroutineContext.minusKey(Job)).launch(start = CoroutineStart.UNDISPATCHED) {
        try {
            selector.select(keeper, SelectInterest.READ)
        } catch (_: Throwable) {
            // the selector closed (or this coroutine was cancelled with it): nothing to keep any more
        } finally {
            keeper.close()
        }
    }
}

/** The [Selectable] of [pipe]'s read end; its [interestedOps] stay READ for the selector's lifetime. */
private class PipeKeeper(
    private val pipe: Pipe,
) : Selectable {
    private val closed = AtomicBoolean(false)

    @Volatile
    private var ops = 0

    override val suspensions: InterestSuspensionsMap = InterestSuspensionsMap()

    override val isClosed: Boolean get() = closed.get()

    override val interestedOps: Int get() = ops

    override val channel: SelectableChannel get() = pipe.source()

    override fun interestOp(
        interest: SelectInterest,
        state: Boolean,
    ) {
        ops = if (state) ops or interest.flag else ops and interest.flag.inv()
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        ops = 0
        runCatching { pipe.source().close() }
        runCatching { pipe.sink().close() }
    }

    override fun dispose() = close()
}
