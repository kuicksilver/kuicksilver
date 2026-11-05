// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CancellationException
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.Source
import kotlin.concurrent.Volatile

/**
 * The content of one HTTP/2 stream as the application reads it. Bytes move from the stream to this channel only when the
 * application waits for content ([awaitContent]), and only then are they credited to the peer
 * (`H2ConnectionCore.consumed`): the peer's sending follows the application's reading (RFC 9113 section 5.2), and the
 * memory a stream holds stays within its receive window.
 *
 * Only the peer's END_STREAM, after a message that passed its checks, is the end (`isClosedForRead`, -1 from
 * `readAvailable`); a reset, a lost connection or a malformed message fails every read with its cause instead, as
 * kuicksilver-quic's stream input does: ktor-io's own channels answer -1 for a channel closed with a cause, which an
 * application cannot tell from a complete body (CONTRIBUTING, "A failed channel is not an end").
 */
@OptIn(InternalAPI::class)
internal class H2BodyChannel(
    private val s: StreamRt,
) : ByteReadChannel {
    private val buffer = Buffer()

    @Volatile private var eof = false

    @Volatile override var closedCause: Throwable? = null
        private set

    override val readBuffer: Source get() {
        closedCause?.let { throw it }
        return buffer
    }

    override val isClosedForRead: Boolean get() = closedCause == null && eof && buffer.exhausted()

    override suspend fun awaitContent(min: Int): Boolean {
        closedCause?.let { throw it }
        while (true) {
            if (buffer.size >= min) return true
            if (eof) return false
            for (c in s.conn.pull(s)) buffer.write(c)
            if (buffer.size >= min) return true
            val (ended, failure) = s.conn.lock.withLock { (s.remoteEnded && s.chunks.isEmpty()) to s.failure }
            // a response read to its END_STREAM stays complete, whatever happens to the connection or our sending after
            if (ended) {
                eof = true
                return buffer.size >= min
            }
            if (failure != null) {
                closedCause = failure
                throw failure
            }
            s.readable.receive()
        }
    }

    override fun cancel(cause: Throwable?) {
        if (closedCause != null || (eof && buffer.exhausted())) return
        val c = cause ?: IOException("the response body was cancelled")
        closedCause = c
        buffer.clear()
        s.conn.cancelRead(s, c as? CancellationException ?: CancellationException("the response body was cancelled", c))
    }
}
