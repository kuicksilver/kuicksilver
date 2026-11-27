// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CancellationException
import kotlinx.io.Buffer
import kotlinx.io.IOException
import kotlinx.io.Source
import kotlin.concurrent.Volatile
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

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
 *
 * The buffer belongs to the reader (one coroutine at a time, as every ktor-io channel has): only [awaitContent] and the
 * reads of [readBuffer] change it. [cancel] comes from any thread, often while the reader is in the middle of a read
 * (Ktor's copier into the application's channel, while `execute {}` ends the call and the call job's completion handler
 * cancels again); it only fails the body, once, and resets the stream. The reader drops what is buffered at its next
 * [awaitContent]; a read already under way keeps the bytes it took.
 */
@OptIn(InternalAPI::class)
internal class H2BodyChannel(
    private val s: StreamRt,
) : ByteReadChannel {
    private val buffer = Buffer()

    @Volatile private var eof = false

    /** Set once: the first failure (the stream's, or a cancel) is the one every read throws. */
    private val failure = AtomicReference<Throwable?>(null)

    override val closedCause: Throwable? get() = failure.load()

    override val readBuffer: Source get() {
        closedCause?.let { throw it }
        return buffer
    }

    override val isClosedForRead: Boolean get() = closedCause == null && eof && buffer.exhausted()

    override suspend fun awaitContent(min: Int): Boolean {
        failIfClosed()
        while (true) {
            if (buffer.size >= min) return true
            if (eof) return false
            for (c in s.conn.pull(s)) buffer.write(c)
            failIfClosed() // a cancel that landed meanwhile: what was pulled is dropped with the rest
            if (buffer.size >= min) return true
            val (ended, more, streamFailure) = s.conn.lock.withLock { Triple(s.remoteEnded, s.chunks.isNotEmpty(), s.failure) }
            // a message that arrived to its END_STREAM stays complete, whatever happens to the connection or the stream after
            // (a server's RST_STREAM after a complete response, RFC 9113 section 8.1): its content is read to the end first
            if (ended) {
                if (more) continue
                eof = true
                return buffer.size >= min
            }
            if (streamFailure != null) {
                failure.compareAndSet(null, streamFailure)
                failIfClosed()
            }
            s.readable.receive()
        }
    }

    /** Throws the body's failure, dropping what is buffered (the reader's own thread: nothing else touches the buffer). */
    private fun failIfClosed() {
        val cause = closedCause ?: return
        if (!buffer.exhausted()) buffer.clear()
        throw cause
    }

    /**
     * The application gave up the body: every read fails with [cause] from now on, and the stream is reset with CANCEL
     * unless the peer had already sent all of it (RFC 9113 section 8.1). Idempotent and safe from any thread, against a
     * reader in the middle of a read and against content arriving: the first cancel (or the stream's own failure) wins,
     * the others do nothing, and the buffer is never touched here.
     */
    override fun cancel(cause: Throwable?) {
        // read to its end: nothing is abandoned. A racy look at the buffer's size, which only the reader changes: at worst a
        // body the reader is just finishing is cancelled, and its complete stream is not reset (cancelRead)
        if (eof && buffer.exhausted()) return
        val c = cause ?: IOException("the response body was cancelled")
        if (!failure.compareAndSet(null, c)) return
        s.readable.trySend(Unit) // a reader waiting for content fails now, with c
        s.conn.cancelRead(s, c as? CancellationException ?: CancellationException("the response body was cancelled", c))
    }
}
