// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.io.Buffer
import kotlinx.io.Source
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicReference

/**
 * The application's side of a WebTransport stream's input: chunks the stream's pump took from the transport, handed
 * over one at a time through a single slot ([deliver] waits while it is full), so at most a chunk waits here besides what
 * the application has not read yet. [onRead] hears how many bytes the application took into its buffer, as it asks for
 * them: what the session's flow control gives back as credit (draft-ietf-webtrans-http3-17 section 5.6: "Endpoints
 * SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as they consume data"), not what only arrived.
 *
 * The slot is taken atomically and the wake-ups are conflated signals that carry no data, so a reader cancelled while it
 * waits (a timeout around a read) loses nothing: the chunk stays in the slot for its next read.
 *
 * Like the channel it replaces: only a clean end ([finish], every byte read) is `isClosedForRead`; a failure ([fail],
 * or [cancel]) fails every read at once with its cause, dropping what was not read.
 */
@OptIn(io.ktor.utils.io.InternalAPI::class)
internal class WtInput(
    /** Bytes the application took into its buffer; called on the reader's thread. */
    private val onRead: (Long) -> Unit,
    /** The application cancelled its input. */
    private val onCancel: () -> Unit,
) : ByteReadChannel {
    private val slot = AtomicReference<ByteArray?>(null)

    /** A chunk was put in the slot, or the input ended or failed: the reader looks again. */
    private val filled = Channel<Unit>(Channel.CONFLATED)

    /** The slot was emptied, or the input failed: the pump looks again. */
    private val freed = Channel<Unit>(Channel.CONFLATED)
    private val buf = Buffer()

    @Volatile private var failure: Throwable? = null

    /** Set by [finish], after the last chunk went into the slot. */
    @Volatile private var finished = false

    @Volatile private var ended = false

    /** Pump: hands [chunk] over, waiting while the slot is full; throws once the input failed. */
    suspend fun deliver(chunk: ByteArray) {
        while (true) {
            if (failure != null) throw CancellationException("the WebTransport stream's input is closed")
            if (slot.compareAndSet(null, chunk)) {
                filled.trySend(Unit)
                return
            }
            freed.receive()
        }
    }

    /** Pump: the peer's FIN after every chunk. */
    fun finish() {
        finished = true
        filled.trySend(Unit)
    }

    /** Pump: the stream failed with [cause] (a reset, a stop, the session's end). */
    fun fail(cause: Throwable) {
        if (failure == null) failure = cause
        filled.trySend(Unit)
        freed.trySend(Unit)
    }

    override val closedCause: Throwable? get() = failure

    override val isClosedForRead: Boolean get() = failure == null && ended && buf.exhausted()

    override val readBuffer: Source get() {
        failure?.let { throw it }
        return buf
    }

    override suspend fun awaitContent(min: Int): Boolean {
        while (buf.size < min) {
            failure?.let { throw it }
            // the end is read before the slot: a last chunk put there before finish() is still taken
            val done = finished
            val chunk = slot.exchange(null)
            if (chunk != null) {
                freed.trySend(Unit)
                // taken by the reader, which asked for it: consumed now (whatever the reader then does with its buffer, it
                // holds at most what it asked for and one chunk), so a reader that reads exactly what it needs and then
                // waits on another stream never keeps the credit
                buf.write(chunk)
                onRead(chunk.size.toLong())
                continue
            }
            if (done) {
                ended = true
                break
            }
            filled.receive() // cancellable: nothing is lost, the chunk stays in the slot
        }
        failure?.let { throw it }
        return buf.size >= min
    }

    override fun cancel(cause: Throwable?) {
        if (failure == null) failure = cause ?: kotlinx.io.IOException("the WebTransport stream's input was cancelled")
        filled.trySend(Unit)
        freed.trySend(Unit)
        onCancel()
    }
}
