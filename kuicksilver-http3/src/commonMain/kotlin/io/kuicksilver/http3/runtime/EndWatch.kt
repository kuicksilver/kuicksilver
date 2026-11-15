// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.http3.runtime

import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.selects.select

/**
 * What a stream's reader waiting on the connection's state (the [HeaderBudget], QPACK inserts) also wakes for, without
 * polling: the peer aborting its half of the stream ([streamAborted], `QuicStream.receiveAborted`: a RESET_STREAM or a
 * rejected 0-RTT, never a FIN) and [connectionEnd]. [giveUp] turns either into what the reader throws: with the stream's
 * abort cause, or with null when the connection ended (null back: the reader goes on waiting, never woken by it again).
 */
internal class EndWatch(
    private val streamAborted: Deferred<Throwable>?,
    private val connectionEnd: Job,
    private val giveUp: (streamCause: Throwable?) -> Throwable?,
) {
    /** Returns once [ready] completed; throws what [giveUp] gives when the stream is aborted or the connection ends first. */
    suspend fun await(ready: Job) {
        var connection: Job? = connectionEnd
        while (true) {
            val woke =
                select<Int> {
                    ready.onJoin { READY }
                    streamAborted?.onJoin { ABORTED }
                    connection?.onJoin { CONNECTION }
                }
            when (woke) {
                READY -> {
                    return
                }

                ABORTED -> {
                    throw giveUp(streamAborted!!.getCompleted()) ?: error("an aborted stream must give up")
                }

                else -> {
                    giveUp(null)?.let { throw it }
                    connection = null
                }
            }
        }
    }

    private companion object {
        const val READY = 0
        const val ABORTED = 1
        const val CONNECTION = 2
    }
}
