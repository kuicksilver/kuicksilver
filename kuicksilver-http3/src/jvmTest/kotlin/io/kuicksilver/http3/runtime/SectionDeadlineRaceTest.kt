// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.VarInt
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertIs
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource

/**
 * A HEADERS section (a response head, a request's trailers) read whole as `maxHeaderBlockTime` fires is the section:
 * the timeout lands on another thread after the read returned and before the deadline's scope completed, and the stream
 * must not fail with H3_REQUEST_CANCELLED for a frame that arrived.
 */
class SectionDeadlineRaceTest {
    @Test fun negative_aSectionReadAsItsDeadlineFiresIsTheSection(): Unit =
        runBlocking {
            val payload = byteArrayOf(0, 0, 0x51)
            var deadline = 100.milliseconds
            // a run whose read did not end before the deadline (a cold or loaded JVM) does not reach the race: it is
            // repeated with the deadline doubled, and only a run that reached it is judged
            repeat(6) {
                var reached = false
                val frames =
                    RequestFrames(
                        ByteReadChannel(VarInt.encode(FrameType.HEADERS) + VarInt.encode(payload.size.toLong()) + payload),
                        isServerSide = true,
                        maxHeadersFrame = 1024,
                        sectionDeadline = deadline,
                        streamId = 0,
                        afterSectionForTest = { job ->
                            // the read of a section on the wire ends through a resumption (its bytes arrive later): the
                            // block completes dispatched, as it does in a connection; throws once the deadline fired
                            yield()
                            reached = true
                            val giveUp = TimeSource.Monotonic.markNow() + 30_000.milliseconds
                            while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the deadline fires
                        },
                    )
                val started = TimeSource.Monotonic.markNow()
                // on Dispatchers.Default the timeout fires on another thread while the hook holds this one
                val got = withContext(Dispatchers.Default) { runCatching { frames.next() } }
                if (!reached || started.elapsedNow() < deadline) {
                    deadline *= 2
                    return@repeat
                }
                val headers = assertIs<RequestFrame.Headers>(got.getOrThrow(), "the section read as the deadline fired")
                assertContentEquals(payload, headers.block)
                return@runBlocking
            }
            fail("no run reached the race (the section was never read before its deadline)")
        }
}
