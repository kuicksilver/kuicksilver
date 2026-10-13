// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.channels.Channel
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.io.readByteArray

/**
 * A byte pipe that holds at most about [chunk] x ([chunks] + 1) bytes in flight: a write blocks until the reader took what
 * was written before, as a TCP connection whose windows are full. ktor's ByteChannel accepts a megabyte before it pushes
 * back, which hides a writer that stops its own reader.
 */
@OptIn(InternalAPI::class)
internal class BoundedPipe(
    private val chunk: Int = 4096,
    chunks: Int = 1,
) {
    private val queue = Channel<ByteArray>(chunks)

    val write: ByteWriteChannel =
        object : ByteWriteChannel {
            private val buffer = Buffer()
            private var cause: Throwable? = null
            private var closed = false

            override val isClosedForWrite: Boolean get() = closed

            override val closedCause: Throwable? get() = cause

            override val writeBuffer: Sink get() = buffer

            override suspend fun flush() {
                cause?.let { throw it }
                while (!buffer.exhausted()) queue.send(buffer.readByteArray(minOf(chunk.toLong(), buffer.size).toInt()))
            }

            override suspend fun flushAndClose() {
                if (closed) return
                flush()
                closed = true
                queue.close()
            }

            override fun cancel(cause: Throwable?) {
                if (closed) return
                closed = true
                this.cause = cause
                queue.close(cause)
            }
        }

    val read: ByteReadChannel =
        object : ByteReadChannel {
            private val buffer = Buffer()
            private var cause: Throwable? = null
            private var ended = false

            override val closedCause: Throwable? get() = cause

            override val isClosedForRead: Boolean get() = (ended || cause != null) && buffer.exhausted()

            override val readBuffer: Source get() = buffer

            override suspend fun awaitContent(min: Int): Boolean {
                while (buffer.size < min && !ended && cause == null) {
                    val r = queue.receiveCatching()
                    val bytes = r.getOrNull()
                    if (bytes == null) {
                        r.exceptionOrNull()?.let { cause = it }
                        ended = true
                    } else {
                        buffer.write(bytes)
                    }
                }
                return buffer.size >= min
            }

            override fun cancel(cause: Throwable?) {
                if (this.cause == null) this.cause = cause ?: IllegalStateException("cancelled")
                queue.cancel()
            }
        }
}
