// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.http3.runtime

import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.yield

/**
 * What a stream's reader waiting on the connection's state (the [HeaderBudget], QPACK inserts) also wakes for, without
 * polling: the end of the peer's half of its stream ([streamEnd], `QuicStream.receivedFinalSize`: a FIN, a reset, or
 * the stream lost with its connection) and [connectionEnd]. When either ends, [abandoned] says whether the reader gives
 * up, and with what.
 */
internal class EndWatch(
    private val streamEnd: Deferred<*>?,
    private val connectionEnd: Job,
    /** A [streamEnd] that failed (the stream lost with its connection) is thrown; else the wait goes on for the rest. */
    private val streamLossFails: Boolean = true,
    private val abandoned: () -> Throwable?,
) {
    /**
     * Returns once [ready] completed; throws what [abandoned] gives when the stream or the connection ends first, or the
     * failure of [streamEnd] (its stream was lost) with [streamLossFails]. A FIN gives nothing to throw: the reader goes on waiting for [ready]
     * and the connection only (the stream's bytes are all there).
     */
    suspend fun await(ready: Job) {
        var stream = streamEnd
        var connection: Job? = connectionEnd
        while (true) {
            val isReady =
                select<Boolean> {
                    ready.onJoin { true }
                    stream?.onJoin { false }
                    connection?.onJoin { false }
                }
            if (isReady) return
            // a RESET_STREAM may be surfaced to the input right after its final size: look once more after it
            abandoned()?.let { throw it }
            yield()
            abandoned()?.let { throw it }
            if (streamLossFails) stream?.let { s -> if (s.isCompleted) s.getCompletionExceptionOrNull()?.let { throw it } }
            if (stream?.isCompleted == true) stream = null
            if (connection?.isCompleted == true) connection = null // nothing to give up for: never wake for it again
        }
    }
}
