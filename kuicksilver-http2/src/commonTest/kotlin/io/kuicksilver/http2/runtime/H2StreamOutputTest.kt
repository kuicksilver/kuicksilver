// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(
    io.kuicksilver.annotations.InternalKuicksilverApi::class,
    io.ktor.utils.io.InternalAPI::class,
    kotlinx.coroutines.ExperimentalCoroutinesApi::class,
)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The engines' WebSocket output over an HTTP/2 stream: its writer is held at [limit] bytes ahead of what the stream took
 * (RFC 9113 section 5.2 backpressure, not a Ktor ByteChannel's megabytes), the end is END_STREAM, a cancel is not.
 */
class H2StreamOutputTest {
    private val limit = 65_536
    private val frame = 16_388

    /** A stream that takes nothing (no window): the writer's flushes stop at the limit. */
    @Test fun negative_writerIsHeldAtTheLimit() =
        runTest {
            val never = CompletableDeferred<Unit>()
            val out = H2StreamOutput(backgroundScope, limit) { _, _ -> never.await() }
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
            assertTrue(writer.isActive, "the writer waits")
            // nothing was taken by the stream: the flushes that returned are within the limit, and the next one (the frame
            // that would pass it) waits
            assertTrue(flushed in (limit - frame + 1).toLong()..limit.toLong(), "flushed $flushed")
            writer.cancel()
        }

    /** What the stream takes releases the writer; flushAndClose ends the stream after every byte, in order. */
    @Test fun everyByteThenEndStream() =
        runTest {
            val got = ArrayList<Byte>()
            var ended = 0
            val out =
                H2StreamOutput(backgroundScope, limit) { source, end ->
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

    /** A stream that fails (a reset, the stall deadline) fails the writer's next call with its cause, never the scope. */
    @Test fun negative_aFailedStreamFailsTheWriter() =
        runTest {
            val reset = kotlinx.io.IOException("reset")
            val out = H2StreamOutput(backgroundScope, limit) { _, _ -> throw reset }
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
            val out = H2StreamOutput(backgroundScope, limit) { _, end -> if (end) ended = true }
            out.writeFully(ByteArray(10))
            out.flush()
            out.cancel(kotlinx.io.IOException("the session failed"))
            out.done.join()
            assertTrue(!ended)
            assertNotNull(out.closedCause)
        }
}
