// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.SocketTimeoutException
import io.ktor.client.request.HttpRequestData
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlin.concurrent.atomics.AtomicBoolean
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * Progress of one exchange, in either direction, for the socket timeout. Ktor defines `socketTimeoutMillis` as the
 * "maximum time of inactivity between two data packets", and the CIO engine applies it to every socket read and write.
 * Here one timer ([within]) covers a phase that sends and receives at once (a request body going out while the
 * response head is awaited) and restarts at every [tick]: the body's progress and the response's bytes both count, so
 * an upload that keeps moving never times out, and one that stalls (the peer stops reading, the application stops
 * writing) times out [within]'s `millis` after its last progress.
 */
internal class Activity {
    private val ticks = MutableStateFlow(0L)

    /** Data moved. */
    fun tick() {
        ticks.update { it + 1 }
    }

    /**
     * Runs [block]; when [millis] pass without a [tick], [onExpiry] runs, [block] is cancelled and [timeout] is thrown
     * instead. [onExpiry] is for a [block] that cancellation does not reach (one that switches to another `Job`, as the
     * vendored response reader does with the call's context): closing its connection ends its wait. Whichever ends
     * first wins: once [block] has returned or thrown, an expiry that fired at the same moment is dropped (the watchdog
     * can still run after its cancellation, which does not stop a timer that already fired, or on another thread).
     */
    @OptIn(ExperimentalAtomicApi::class)
    suspend fun <T> within(
        millis: Long,
        timeout: (CancellationException) -> Throwable,
        onExpiry: () -> Unit = {},
        block: suspend () -> T,
    ): T {
        var expired: Inactive? = null
        val settled = AtomicBoolean(false) // claimed by the first of the block's end and the expiry
        try {
            return coroutineScope {
                val scope = this
                val watchdog =
                    launch {
                        var seen = ticks.value
                        while (true) seen = withTimeoutOrNull(millis) { ticks.first { it != seen } } ?: break
                        if (!settled.compareAndSet(false, true)) return@launch // the block ended first
                        val inactive = Inactive(millis)
                        expired = inactive
                        onExpiry()
                        scope.cancel(inactive)
                    }
                try {
                    block()
                } finally {
                    settled.compareAndSet(false, true)
                    watchdog.cancel()
                }
            }
        } catch (e: Throwable) {
            // cancelled, or failed because [onExpiry] closed what it was waiting on
            currentCoroutineContext().ensureActive() // the caller was cancelled: not a timeout
            expired?.let { throw timeout(it) }
            throw e
        }
    }

    private class Inactive(
        millis: Long,
    ) : CancellationException("no data moved for $millis ms")
}

/**
 * [block] under [request]'s socket timeout as an inactivity timeout over [activity] (see [Activity.within] for
 * [onExpiry]); no timeout when either is absent.
 */
internal suspend fun <T> withSocketInactivityTimeout(
    request: HttpRequestData,
    activity: Activity?,
    onExpiry: () -> Unit = {},
    block: suspend () -> T,
): T {
    val millis = request.socketTimeoutMillis()
    if (millis == null || activity == null) return block()
    return activity.within(millis, { SocketTimeoutException(request, it) }, onExpiry, block)
}

/** [delegate], with a [Activity.tick] at every flush: the bytes before it were taken by the transport. */
@OptIn(InternalAPI::class)
internal class ActivityOutput(
    private val delegate: ByteWriteChannel,
    private val activity: Activity,
) : ByteWriteChannel {
    override val isClosedForWrite: Boolean get() = delegate.isClosedForWrite
    override val closedCause: Throwable? get() = delegate.closedCause
    override val writeBuffer: Sink get() = delegate.writeBuffer

    override suspend fun flush() {
        delegate.flush()
        activity.tick()
    }

    override suspend fun flushAndClose() {
        delegate.flushAndClose()
        activity.tick()
    }

    override fun cancel(cause: Throwable?) {
        delegate.cancel(cause)
    }
}

/**
 * [delegate], with a [Activity.tick] whenever data arrives. Reads go straight to [delegate]'s buffer (as
 * [SocketTimeoutChannel]), so wrapping a connection's input for one response head never reads past it.
 */
@OptIn(InternalAPI::class)
internal class ActivityInput(
    private val delegate: ByteReadChannel,
    private val activity: Activity,
) : ByteReadChannel {
    override val closedCause: Throwable? get() = delegate.closedCause
    override val isClosedForRead: Boolean get() = delegate.isClosedForRead
    override val readBuffer: Source get() = delegate.readBuffer

    override suspend fun awaitContent(min: Int): Boolean = delegate.awaitContent(min).also { activity.tick() }

    override fun cancel(cause: Throwable?) {
        delegate.cancel(cause)
    }
}

/**
 * A request body as its sender consumes it, with a [Activity.tick] at each step: [delegate]'s bytes are handed on at
 * most [step] at a time, so the sender comes back for more (and ticks) after every [step] bytes it took, and stops
 * ticking when it stops taking (flow control, a peer that does not read) or [delegate] stops giving.
 */
@OptIn(InternalAPI::class)
internal class ConsumedBody(
    private val delegate: ByteReadChannel,
    private val activity: Activity,
    private val step: Long = DEFAULT_STEP,
) : ByteReadChannel {
    private val buffer = Buffer()

    override val closedCause: Throwable? get() = delegate.closedCause
    override val isClosedForRead: Boolean get() = buffer.exhausted() && delegate.isClosedForRead
    override val readBuffer: Source get() = buffer

    override suspend fun awaitContent(min: Int): Boolean {
        activity.tick() // the sender took what it had
        while (buffer.size < min) {
            val from = delegate.readBuffer
            if (from.exhausted() && !delegate.awaitContent()) return buffer.size >= min
            from.readAtMostTo(buffer, maxOf(step, min - buffer.size))
            activity.tick()
        }
        return true
    }

    override fun cancel(cause: Throwable?) {
        buffer.clear()
        delegate.cancel(cause)
    }

    private companion object {
        const val DEFAULT_STEP = 16L * 1024
    }
}
