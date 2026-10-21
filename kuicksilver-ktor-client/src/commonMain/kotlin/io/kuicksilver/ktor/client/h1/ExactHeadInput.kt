// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.io.Buffer
import kotlinx.io.Source

/**
 * [source] for reading one head that must not take a byte past its end, at most [maxBytes] of it: a reader gets one byte
 * per wait, so the parser stops at the head's empty line and what follows stays in [source] (the proxy's CONNECT
 * response, after which the bytes are the tunnel's). A reader that wants more than [maxBytes] sees the channel end and
 * [exceeded] turns true. One byte per wait is slow, but a CONNECT head is read once per connection.
 */
@OptIn(InternalAPI::class)
internal class ExactHeadInput(
    private val source: ByteReadChannel,
    private val maxBytes: Int,
) : ByteReadChannel {
    private val buffer = Buffer()
    private var taken = 0

    /** Whether the reader wanted more than [maxBytes]. */
    var exceeded: Boolean = false
        private set

    override val closedCause: Throwable? get() = source.closedCause

    override val isClosedForRead: Boolean
        get() = buffer.exhausted() && (exceeded || source.isClosedForRead)

    override val readBuffer: Source get() = buffer

    override suspend fun awaitContent(min: Int): Boolean {
        while (buffer.size < min) {
            if (taken >= maxBytes) {
                exceeded = true
                return false
            }
            val from = source.readBuffer
            if (from.exhausted() && !source.awaitContent()) return false
            if (from.readAtMostTo(buffer, 1L) > 0) taken++
        }
        return true
    }

    override fun cancel(cause: Throwable?) {
        buffer.clear()
        source.cancel(cause)
    }
}
