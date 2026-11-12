// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.ktor.utils.io.InternalAPI::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ClosedWriteChannelException
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The engines' WebSocket output over an HTTP/2 stream: its writer is held at `limit` flushed bytes ahead of what the
 * stream took (RFC 9113 section 5.2 backpressure, not a Ktor ByteChannel's megabytes); an orderly close is END_STREAM
 * without waiting for the lead; a cancelled session never ends the stream (RFC 8441 section 5: the owner resets it).
 */
class H2StreamOutputTest {
    private val limit = H2StreamOutput.DEFAULT_LIMIT
    private val frame = 16_388

    /** A stream that takes nothing (no window): the writer's flushes stop at the limit, and it waits there. */
    @Test fun negative_writerIsHeldAtTheLimit() =
        runTest {
            val never = CompletableDeferred<Unit>()
            val out = H2StreamOutput(backgroundScope) { _, _ -> never.await() }
            var flushed = 0L
            val writer =
                backgroundScope.launch {
                    while (true) {
                        out.writeFully(ByteArray(frame))
                        out.flush()
                        flushed += frame
                    }
                }
            runCurrent()
            assertTrue(out.writerWaiting.value, "the writer waits")
            // nothing was taken by the stream (the first piece is still being sent): the flushes that returned are within
            // the limit, and the one that went past it waits
            assertTrue(flushed in (limit - frame + 1).toLong()..limit.toLong(), "flushed $flushed")
            assertTrue(out.lead in (limit + 1).toLong()..(limit + frame).toLong(), "lead ${out.lead}")
            writer.cancel()
        }

    /** What the stream takes releases the writer; flushAndClose ends the stream after every byte, in order. */
    @Test fun everyByteThenEndStream() =
        runTest {
            val got = ArrayList<Byte>()
            var ended = 0
            val out =
                H2StreamOutput(backgroundScope) { source, end ->
                    got += source.readBuffer().readByteArray().toList()
                    if (end) ended++
                }
            val data = ByteArray(1_000_000) { (it * 7).toByte() }
            out.writeFully(data)
            out.flushAndClose()
            out.done.join()
            assertContentEquals(data, got.toByteArray())
            assertEquals(1, ended)
            assertTrue(out.endedInOrder)
        }

    /**
     * flushAndClose does not wait for the lead: the stream's end must not wait for a window the peer may never open (the
     * owner bounds that, the client engine with its close wait). Before, a last frame larger than the lead held the
     * closing writer, inside the call, for good.
     */
    @Test fun negative_flushAndCloseDoesNotWaitForTheLead() =
        runTest {
            val never = CompletableDeferred<Unit>()
            val out = H2StreamOutput(backgroundScope) { _, _ -> never.await() }
            val closing =
                backgroundScope.async {
                    out.writeFully(ByteArray(300_000))
                    out.flushAndClose()
                }
            runCurrent()
            assertTrue(closing.isCompleted, "flushAndClose returned")
            assertTrue(out.isClosedForWrite)
        }

    /**
     * A session cancelled after its flushAndClose, with the rest not sent yet, never ends the stream: RFC 8441 section 5,
     * a session that did not end in order is a RST_STREAM CANCEL (the owner's), never an END_STREAM.
     */
    @Test fun negative_cancelAfterFlushAndCloseSendsNoEndStream() =
        runTest {
            val firstPiece = CompletableDeferred<Unit>()
            var ended = false
            val out =
                H2StreamOutput(backgroundScope) { _, end ->
                    firstPiece.await()
                    if (end) ended = true
                }
            backgroundScope.launch {
                out.writeFully(ByteArray(3 * limit))
                runCatching { out.flushAndClose() }
            }
            runCurrent()
            out.cancel(kotlinx.io.IOException("the call was cancelled"))
            firstPiece.complete(Unit)
            out.done.join()
            assertFalse(ended, "no END_STREAM after a cancel")
            assertFalse(out.endedInOrder)
        }

    /** A cancel wakes a writer that waits for the stream, and its flush throws the cause; a later write too. */
    @Test fun negative_cancelWakesAWaitingWriter() =
        runTest {
            val never = CompletableDeferred<Unit>()
            val out = H2StreamOutput(backgroundScope) { _, _ -> never.await() }
            val writer =
                backgroundScope.async {
                    runCatching {
                        while (true) {
                            out.writeFully(ByteArray(frame))
                            out.flush()
                        }
                    }.exceptionOrNull()
                }
            runCurrent()
            assertTrue(out.writerWaiting.value)
            val cause = kotlinx.io.IOException("the session failed")
            out.cancel(cause)
            runCurrent()
            assertTrue(writer.isCompleted, "the writer woke")
            assertSame(cause, writer.await())
            assertSame(cause, assertFailsWith<kotlinx.io.IOException> { out.flush() })
        }

    /** After an orderly close, a write is a ClosedWriteChannelException. */
    @Test fun negative_writeAfterCloseFails() =
        runTest {
            val out = H2StreamOutput(backgroundScope) { _, _ -> }
            out.flushAndClose()
            assertFailsWith<ClosedWriteChannelException> { out.writeFully(ByteArray(1)) }
        }

    /** A stream that fails (a reset, the stall deadline) fails the writer's next call with its cause, never the scope. */
    @Test fun negative_aFailedStreamFailsTheWriter() =
        runTest {
            val reset = kotlinx.io.IOException("reset")
            val out = H2StreamOutput(backgroundScope) { _, _ -> throw reset }
            out.writeFully(ByteArray(10))
            runCatching { out.flush() }
            out.done.join()
            assertEquals(reset, out.failed)
            assertFailsWith<kotlinx.io.IOException> {
                out.writeFully(ByteArray(10))
                out.flush()
            }
        }

    /** A cancelled writer (a session that failed) does not end the stream: the owner resets it. */
    @Test fun negative_cancelIsNoEndStream() =
        runTest {
            var ended = false
            val out = H2StreamOutput(backgroundScope) { _, end -> if (end) ended = true }
            out.writeFully(ByteArray(10))
            out.flush()
            out.cancel(kotlinx.io.IOException("the session failed"))
            out.done.join()
            assertFalse(ended)
            assertNotNull(out.closedCause)
            assertNull(out.failed)
        }
}
