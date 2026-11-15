// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.http3.runtime

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedSendChannelException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.FlowCollector
import kotlin.concurrent.atomics.AtomicInt

/**
 * A FIFO that hands elements carrying data or ownership (a capsule, a request, a peer's stream) from producers to
 * consumers without losing one to cancellation. A coroutine channel's `receive` has a prompt cancellation guarantee: an
 * element already handed to a receiver that is cancelled before it resumes (a timeout, a `select`) is gone unless the
 * channel has `onUndeliveredElement`. Here an element leaves the queue only inside [receive] while the receiver runs,
 * with no suspension between taking it and returning it; the channels underneath carry only wake-ups, which are
 * re-sent when a waiter is cancelled, so no other waiter misses one.
 *
 * [send] waits while [capacity] elements are held (back-pressure); [offer] never waits and is for unbounded queues.
 * Elements still held when the queue is closed are received first, then [receive] answers null (closed without a
 * cause) or throws the cause, as a closed channel does.
 *
 * What the queue guarantees ends where [receive] returns: a caller that wraps the call in `withTimeout`, `async` or
 * `withContext` can still have that wrapper drop an element it returned (the wrapper discards the result of a block whose
 * coroutine was cancelled while it ran, as kotlinx.coroutines documents). Hand elements on from the receiving
 * coroutine itself, as [asFlow] does, and keep such wrappers out of the path.
 */
internal class HandOffQueue<T : Any>(
    private val capacity: Int = Int.MAX_VALUE,
) {
    private val lock = AtomicInt(0)
    private val items = ArrayDeque<T>()
    private var closed = false
    private var cause: Throwable? = null

    /** Signalled when an element was added or the queue closed. */
    private val filled = Channel<Unit>(Channel.CONFLATED)

    /** Signalled when an element was taken or the queue closed; only a bounded queue has senders that wait for it. */
    private val drained: Channel<Unit>? = if (capacity == Int.MAX_VALUE) null else Channel(Channel.CONFLATED)

    private inline fun <R> locked(block: () -> R): R {
        while (!lock.compareAndSet(0, 1)) {
            // sections are a few deque operations: nothing in them suspends or blocks
        }
        try {
            return block()
        } finally {
            lock.store(0)
        }
    }

    /** Adds [e] at the end without waiting; false when the queue is closed or full. */
    fun offer(e: T): Boolean {
        val added = locked { if (closed || items.size >= capacity) false else items.addLast(e).let { true } }
        if (added) filled.trySend(Unit)
        return added
    }

    /**
     * Puts [e] back at the head, ahead of everything queued, even past [capacity]: an element a receiver took but could
     * not hand to its caller. False when the queue is closed (the caller then disposes of [e]).
     */
    fun putBack(e: T): Boolean {
        val added = locked { if (closed) false else items.addFirst(e).let { true } }
        if (added) filled.trySend(Unit)
        return added
    }

    /** Adds [e] at the end, waiting while the queue is full; throws [ClosedSendChannelException] once it is closed. */
    suspend fun send(e: T) {
        while (true) {
            var room = false
            val r =
                locked {
                    when {
                        closed -> {
                            null
                        }

                        items.size < capacity -> {
                            items.addLast(e)
                            room = items.size < capacity
                            true
                        }

                        else -> {
                            false
                        }
                    }
                }
            when (r) {
                null -> {
                    throw ClosedSendChannelException("the queue was closed")
                }

                true -> {
                    filled.trySend(Unit)
                    if (room) drained?.trySend(Unit) // another sender may have slept through the one signal for several places
                    return
                }

                false -> {
                    await(drained!!) // full: only a bounded queue gets here
                }
            }
        }
    }

    /** The next element; null once the queue is closed without a cause and empty, the cause when closed with one. */
    suspend fun receive(): T? {
        while (true) {
            tryTake()?.let { return it }
            if (locked { closed && items.isEmpty() }) {
                cause?.let { throw it }
                return null
            }
            await(filled)
        }
    }

    /** The next element when one is held, else null; never waits. */
    fun tryTake(): T? {
        var more = false
        val e = locked { items.removeFirstOrNull().also { more = items.isNotEmpty() } } ?: return null
        drained?.trySend(Unit)
        if (more) filled.trySend(Unit) // another waiter may have slept through the one signal for several elements
        return e
    }

    /** Takes no more elements; those held stay receivable. Waiting senders fail, waiting receivers see the end once empty. */
    fun close(cause: Throwable? = null): Boolean {
        val first =
            locked {
                if (closed) {
                    false
                } else {
                    closed = true
                    this.cause = cause
                    true
                }
            }
        filled.trySend(Unit)
        drained?.trySend(Unit)
        return first
    }

    /** Elements held now (tests). */
    val size: Int get() = locked { items.size }

    /**
     * The elements as a flow, each taken only when the collector is about to get it. Not a `flow {}` builder: its `emit`
     * checks the collector's job after the element was taken, so a collector cancelled while it handled the element
     * before would drop the next one. Here the check comes first, before anything is taken.
     */
    fun asFlow(): Flow<T> =
        object : Flow<T> {
            override suspend fun collect(collector: FlowCollector<T>) {
                while (true) {
                    currentCoroutineContext().ensureActive()
                    collector.emit(receive() ?: break)
                }
            }
        }

    /** Waits for a signal of [ch]; a waiter cancelled meanwhile passes on a signal it may have consumed. */
    private suspend fun await(ch: Channel<Unit>) {
        try {
            ch.receive()
        } catch (e: CancellationException) {
            ch.trySend(Unit)
            throw e
        }
        // a closed queue keeps every waiter going: the next one finds the state itself
        if (locked { closed }) ch.trySend(Unit)
    }
}
