// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.readAvailable
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The hand-off of [WtInput], one reader and one pump on a single thread, so every interleaving is fixed. */
class WtInputTest {
    /**
     * A reader cancelled after its chunk was handed over but before it ran again (its wake-up queued, the cancellation
     * first) leaves the chunk for its next read, with no credit given for it; the wake-up carries no data. With a channel
     * of chunks the cancelled receive took the chunk with it and the next read saw only the end.
     */
    @Test fun negative_readerCancelledAsItsChunkArrivesLosesNothing() =
        runBlocking {
            var credited = 0L
            val input = WtInput(onRead = { credited += it }, onCancel = {})
            val reader = launch(start = CoroutineStart.UNDISPATCHED) { input.awaitContent(1) } // waits: nothing yet
            input.deliver(byteArrayOf(1, 2, 3)) // the reader's wake-up is queued on this thread
            reader.cancel() // before the reader runs
            reader.join()
            assertTrue(reader.isCancelled)
            assertEquals(0L, credited, "credit for a chunk nobody took")
            input.finish()
            val b = ByteArray(8)
            assertEquals(3, input.readAvailable(b, 0, b.size))
            assertContentEquals(byteArrayOf(1, 2, 3), b.copyOf(3))
            assertEquals(3L, credited)
            assertEquals(-1, input.readAvailable(b, 0, b.size))
        }

    /**
     * Readers cancelled at every point of the hand-off of 50 chunks (waiting, their wake-up queued, after it ran, while
     * the pump waits for the slot) lose nothing: what the reads return is every byte once, in order, and the credit is what
     * arrived.
     */
    @Test fun negative_readersCancelledAtEveryStepLoseNothing() =
        runBlocking {
            var credited = 0L
            val input = WtInput(onRead = { credited += it }, onCancel = {})
            val chunks = List(50) { i -> ByteArray(1 + i % 7) { j -> (i * 7 + j).toByte() } }
            val expected = chunks.fold(ByteArray(0)) { a, c -> a + c }
            val pump =
                launch {
                    for ((i, c) in chunks.withIndex()) {
                        repeat(i % 3) { yield() } // the reader is ahead (waits) or behind (the slot is full)
                        input.deliver(c)
                    }
                    input.finish()
                }
            val got = ArrayList<Byte>()
            val b = ByteArray(4)
            var round = 0
            while (true) {
                var n = -2
                val read = launch(start = CoroutineStart.UNDISPATCHED) { n = input.readAvailable(b, 0, b.size) }
                // cancel after 0 to 3 turns of the event loop: before the pump ran, after it filled the slot and queued the
                // reader's wake-up, after the wake-up ran
                repeat(round % 4) { yield() }
                read.cancel()
                read.join()
                round++
                if (n == -2) continue
                if (n < 0) break
                for (i in 0 until n) got += b[i]
            }
            pump.join()
            assertContentEquals(expected, got.toByteArray())
            assertEquals(expected.size.toLong(), credited)
        }

    /**
     * The peer's reset after a delivered chunk (with RESET_STREAM_AT, the reliable prefix, draft-ietf-webtrans-http3-17
     * section 4.4): the chunk is read first, then the reset; a local failure drops what was not read, as before.
     */
    @Test fun aPeerResetFailsTheReadsAfterTheDeliveredBytes() =
        runBlocking<Unit> {
            val reset = kotlinx.io.IOException("reset by the peer")
            val input = WtInput(onRead = {}, onCancel = {})
            input.deliver("hello".encodeToByteArray())
            input.failAfterData(reset)
            val buf = ByteArray(16)
            assertEquals(5, input.readAvailable(buf, 0, buf.size))
            assertContentEquals("hello".encodeToByteArray(), buf.copyOf(5))
            assertEquals(reset, kotlin.test.assertFailsWith<kotlinx.io.IOException> { input.readAvailable(buf, 0, buf.size) })

            val stopped = WtInput(onRead = {}, onCancel = {})
            stopped.deliver("lost".encodeToByteArray())
            stopped.fail(reset)
            kotlin.test.assertFailsWith<kotlinx.io.IOException> { stopped.readAvailable(buf, 0, buf.size) }
        }

    /**
     * The pump delivers its last chunk and the peer's reset just after the reader found the slot empty: the reader still
     * takes the chunk before the reset (draft-ietf-quic-reliable-stream-reset section 3, the Reliable Size is delivered).
     * The interleaving is forced by [WtInput.afterEmptySlotForTest]; before, the reader read the reset after the slot and
     * threw with the chunk left in it.
     */
    @Test fun negative_aChunkDeliveredAsTheResetLandsIsReadFirst() =
        runBlocking<Unit> {
            val reset = kotlinx.io.IOException("reset by the peer")
            val input = WtInput(onRead = {}, onCancel = {})
            input.afterEmptySlotForTest = {
                input.afterEmptySlotForTest = null
                input.deliver(byteArrayOf(42))
                input.failAfterData(reset)
            }
            val buf = ByteArray(4)
            assertEquals(1, input.readAvailable(buf, 0, buf.size))
            assertEquals(42, buf[0].toInt())
            assertEquals(reset, kotlin.test.assertFailsWith<kotlinx.io.IOException> { input.readAvailable(buf, 0, buf.size) })
        }
}
