// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.concurrent.Volatile

/**
 * The send failures of a TCP socket's write loop, for its read side: a connection that failed under a write did not end.
 *
 * A socket reports a pending error (a reset, a timeout) to the first system call that looks at it, and on Linux (Android
 * included) that call clears it: when the write loop's send runs between the arrival of the peer's reset and the read
 * loop's next receive, the send fails with ECONNRESET and the receive then returns 0, the value of an orderly end. A body
 * delimited by the connection's close (RFC 9112 section 6.3 item 8) then passed cut for complete (section 8). So every
 * send runs through [send], which records its failure before the next [settled] can look, and the read loop asks
 * [settled] when its receive returned the end: the failure recorded, if any, is the read side's failure too. A send that is
 * under way when the end is read is waited for: its failure may be the error the end stands for.
 *
 * Only the system's verdict on a send is recorded, never the application's: a failed application channel or an abort is
 * the local side's decision, and an orderly local close sends nothing that fails.
 */
internal class SendFailures {
    private val sending = Mutex()

    @Volatile private var failure: Throwable? = null

    /** The first send failure recorded, without waiting for a send under way. */
    val recorded: Throwable? get() = failure

    /**
     * Runs [block], a send system call, and records what it throws when [isSystemFailure] says it is the system's verdict on
     * the connection (not a cancellation), before the failure propagates and before a [settled] can return.
     */
    suspend fun <T> send(
        isSystemFailure: (Throwable) -> Boolean = { true },
        block: suspend () -> T,
    ): T =
        sending.withLock {
            try {
                block()
            } catch (e: Throwable) {
                if (e !is CancellationException && isSystemFailure(e) && failure == null) failure = e
                throw e
            }
        }

    /** The send failure recorded once no send is under way, or null: what an end of stream read now stands for. */
    suspend fun settled(): Throwable? {
        sending.withLock {}
        return failure
    }
}
