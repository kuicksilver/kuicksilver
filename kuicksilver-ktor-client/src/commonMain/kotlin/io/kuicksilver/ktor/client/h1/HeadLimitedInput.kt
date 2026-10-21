// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.io.Buffer
import kotlinx.io.Source

// The same class as kuicksilver-ktor-server's h1/HeadLimitedInput.kt (request heads there): the two engines share no
// module above ktor-network.

/**
 * The input of an HTTP/1.1 connection, with a size limit on response heads. Ktor's `parseResponse` bounds each line at
 * 8 KiB but not the number of lines, so a head could be of any size. Between [startHead] and [endHead] at most
 * [maxHeadBytes] bytes, counted from the first byte of the head, can be read; a reader that wants more sees the
 * channel end and [exceeded] turns true. Outside a head (bodies, upgraded connections) reads are not limited.
 *
 * The bytes pass through a buffer of this channel, which takes from [source] only what a read asks for (at least
 * [CHUNK] bytes outside a head), so what is already buffered when the next head starts stays small.
 */
@OptIn(InternalAPI::class)
internal class HeadLimitedInput(
    private val source: ByteReadChannel,
    private val maxHeadBytes: Int,
) : ByteReadChannel {
    private val buffer = Buffer()

    /** Bytes the current head may still take from [source]; negative outside a head. */
    private var headBudget = -1L

    /** Whether the current head wanted more than [maxHeadBytes]. */
    var exceeded: Boolean = false
        private set

    /** A head starts at the next unread byte. */
    fun startHead() {
        headBudget = (maxHeadBytes - buffer.size).coerceAtLeast(0)
        exceeded = false
    }

    /** The head was read: what follows (a body) is not limited. */
    fun endHead() {
        headBudget = -1
    }

    override val closedCause: Throwable? get() = source.closedCause

    override val isClosedForRead: Boolean
        get() = buffer.exhausted() && (exceeded || source.isClosedForRead)

    override val readBuffer: Source get() = buffer

    override suspend fun awaitContent(min: Int): Boolean {
        while (buffer.size < min) {
            val want =
                if (headBudget >= 0) {
                    if (headBudget == 0L) {
                        exceeded = true
                        return false
                    }
                    headBudget
                } else {
                    maxOf(min - buffer.size, CHUNK)
                }
            val from = source.readBuffer
            if (from.exhausted() && !source.awaitContent()) return false
            val moved = from.readAtMostTo(buffer, want)
            if (moved < 0) return false
            if (headBudget >= 0) headBudget -= moved
        }
        return true
    }

    override fun cancel(cause: Throwable?) {
        buffer.clear()
        source.cancel(cause)
    }

    private companion object {
        /** Bytes taken from the socket's channel at a time outside a head. */
        const val CHUNK = 8_192L
    }
}
