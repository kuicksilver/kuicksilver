// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.channels.Channel
import kotlinx.io.Buffer
import kotlinx.io.Source
import kotlin.concurrent.Volatile

/**
 * The application's side of a WebTransport stream's input: chunks the stream's pump took from the transport, handed
 * over one at a time ([deliver] waits while one is still pending), so at most a chunk waits here besides what the
 * application has not read yet. [onRead] hears how many bytes the application took into its buffer, as it asks for
 * them: what the session's flow control gives back as credit (draft-ietf-webtrans-http3-16 section 5.6: "Endpoints
 * SHOULD send WT_MAX_DATA and WT_MAX_STREAMS capsules as they consume data"), not what only arrived.
 *
 * Like the channel it replaces: only a clean end ([finish], every byte read) is `isClosedForRead`; a failure ([fail],
 * or [cancel]) fails every read at once with its cause, dropping what was not read.
 */
@OptIn(io.ktor.utils.io.InternalAPI::class)
internal class WtInput(
    /** Bytes the application read since the last call; called on the reader's thread. */
    private val onRead: (Long) -> Unit,
    /** The application cancelled its input. */
    private val onCancel: () -> Unit,
) : ByteReadChannel {
    private val chunks = Channel<ByteArray>(1)
    private val buf = Buffer()

    @Volatile private var failure: Throwable? = null

    @Volatile private var ended = false

    /** Pump: hands [chunk] over, waiting while the previous one is not taken. */
    suspend fun deliver(chunk: ByteArray) {
        chunks.send(chunk)
    }

    /** Pump: the peer's FIN after every chunk. */
    fun finish() {
        chunks.close()
    }

    /** Pump: the stream failed with [cause] (a reset, a stop, the session's end). */
    fun fail(cause: Throwable) {
        if (failure == null) failure = cause
        chunks.cancel()
    }

    override val closedCause: Throwable? get() = failure

    override val isClosedForRead: Boolean get() = failure == null && ended && buf.exhausted()

    override val readBuffer: Source get() {
        failure?.let { throw it }
        return buf
    }

    override suspend fun awaitContent(min: Int): Boolean {
        failure?.let { throw it }
        while (buf.size < min) {
            val r = chunks.receiveCatching()
            val chunk = r.getOrNull()
            if (chunk != null) {
                // taken by the reader, which asked for it: consumed now (whatever the reader then does with its buffer, it
                // holds at most what it asked for and one chunk), so a reader that reads exactly what it needs and then
                // waits on another stream never keeps the credit
                buf.write(chunk)
                onRead(chunk.size.toLong())
                continue
            }
            failure?.let { throw it }
            ended = true
            break
        }
        return buf.size >= min
    }

    override fun cancel(cause: Throwable?) {
        if (failure == null) {
            failure = cause ?: kotlinx.io.IOException("the WebTransport stream's input was cancelled")
        }
        chunks.cancel()
        onCancel()
    }
}
