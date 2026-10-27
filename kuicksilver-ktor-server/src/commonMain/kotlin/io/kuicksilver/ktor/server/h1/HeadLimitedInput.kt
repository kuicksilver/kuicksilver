// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.InternalAPI
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.Buffer
import kotlinx.io.Source
import kotlin.time.Duration

/**
 * The input of an HTTP/1.1 connection as its pipeline reads it, with a size limit on request heads. Ktor's
 * `parseRequest` bounds each line at 8 KiB but not the number of lines, so a head could be of any size. Between
 * [startHead] and [endHead] at most [maxHeadBytes] bytes, counted from the first byte of the head, can be read; a reader
 * that wants more sees the channel end and [exceeded] turns true. Outside a head (bodies, upgraded connections) reads
 * are not limited.
 *
 * Between [startBody] and [endBody] every wait for the socket's next bytes has a deadline: none for [bodyTimeout] fails
 * the read with [RequestBodyTimeout]. Each wait has its own, so a body that keeps moving, however slowly, is never cut.
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

    /**
     * The field values of the current head that Ktor's parser would change ([checkRequestHead] sets them; see
     * [requestFields]).
     */
    var keptFieldValues: List<KeptFieldValue> = emptyList()

    /** A request head starts at the next unread byte. */
    fun startHead() {
        headBudget = (maxHeadBytes - buffer.size).coerceAtLeast(0)
        exceeded = false
        keptFieldValues = emptyList()
    }

    /** The head was read: what follows (a body) is not limited. */
    fun endHead() {
        headBudget = -1
    }

    /** The deadline of a wait for body bytes; null outside a body (a head, an upgraded connection). */
    private var bodyTimeout: Duration? = null

    /** The deadline runs only once this completes (`100 Continue` sent, or the handler done); null: at once. */
    private var bodyGate: Job? = null

    /** Completed when the body deadline runs out, before the read fails (copies close their target with the failure). */
    private var bodyTimedOut: CompletableJob? = null

    /**
     * A request body starts: waits for its bytes now have [timeout], once [gate] (if any) has completed; [timedOut] is
     * completed when one runs out, before the read fails with [RequestBodyTimeout].
     */
    fun startBody(
        timeout: Duration,
        gate: Job?,
        timedOut: CompletableJob,
    ) {
        bodyTimeout = timeout
        bodyGate = gate
        bodyTimedOut = timedOut
        bodyBytesArrived = buffer.size
    }

    /** Bytes of the current body that have arrived (were buffered at its start or taken from [source] since). */
    @kotlin.concurrent.Volatile
    var bodyBytesArrived: Long = 0
        private set

    /** The body was read (or failed). */
    fun endBody() {
        bodyTimeout = null
        bodyGate = null
        bodyTimedOut = null
    }

    /** [source]'s `awaitContent()`, under the body deadline inside a body. */
    private suspend fun awaitSource(): Boolean {
        val timeout = bodyTimeout ?: return source.awaitContent()
        val gate = bodyGate
        if (gate != null && !gate.isCompleted) {
            // the client may hold the body back until `100 Continue` (RFC 9110 section 10.1.1): no deadline before it
            val arrived =
                coroutineScope {
                    val data = async(start = CoroutineStart.UNDISPATCHED) { source.awaitContent() }
                    select {
                        data.onAwait { it }
                        gate.onJoin {
                            data.cancel()
                            null
                        }
                    }
                }
            if (arrived != null) return arrived
        }
        return withTimeoutOrNull(timeout) { source.awaitContent() } ?: run {
            bodyTimedOut?.complete()
            throw RequestBodyTimeout(timeout)
        }
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
            if (from.exhausted() && !awaitSource()) return false
            val moved = from.readAtMostTo(buffer, want)
            if (moved < 0) return false
            if (headBudget >= 0) headBudget -= moved
            if (bodyTimeout != null) bodyBytesArrived += moved
        }
        return true
    }

    /**
     * Replaces the buffered byte at [index] with [value]: a request line the server reads as another version
     * ([checkRequestHead]) before the parser sees it.
     */
    fun replaceBufferedByte(
        index: Long,
        value: Byte,
    ) {
        val front = Buffer()
        buffer.readTo(front, index)
        buffer.skip(1)
        front.writeByte(value)
        buffer.transferTo(front)
        front.transferTo(buffer)
    }

    /**
     * Drops what is buffered. The socket's channel is not cancelled: copies cancel their source when they fail or are
     * stopped (a body the handler left unread), and the pipeline may then still read and drop the rest of the input
     * before it closes the connection, which it always does after such a failure.
     */
    override fun cancel(cause: Throwable?) {
        buffer.clear()
    }

    private companion object {
        /** Bytes taken from the socket's channel at a time outside a head. */
        const val CHUNK = 8_192L
    }
}
