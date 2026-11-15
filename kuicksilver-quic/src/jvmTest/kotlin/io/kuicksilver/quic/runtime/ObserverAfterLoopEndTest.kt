// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.api.ApiPair
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A stream's observers read for the first time only after its endpoint closed and the loop's scope ended: the re-check that
 * normally runs on the loop cannot run there any more and runs from its job's completion instead. Each observer still tells
 * what the loop fixed before the end (a size fixed first stands, the half still open tells the loss, the flows their last
 * values), and nothing stays pending.
 */
class ObserverAfterLoopEndTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun aFirstReadAfterTheLoopEndedStillSettlesEveryObserver() =
        runBlocking {
            // closed by use() too when anything fails before the explicit close (closing twice is a no-op)
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi() as StreamRuntime
                    st.output.writeFully(ByteArray(1234), 0, 1234)
                    st.output.flushAndClose()
                    val ss = s.acceptStream() as StreamRuntime
                    assertEquals(
                        1234,
                        ss.input
                            .readBuffer()
                            .readByteArray()
                            .size,
                    )
                    // both endpoints close with the streams' other halves still open; their loops' scopes end
                    p.close()
                    for (loop in listOf(st.loop, ss.loop)) {
                        val job = loop.scope.coroutineContext[Job]!!
                        job.join()
                        assertTrue(job.isCancelled, "the loop's scope ended")
                    }
                    assertEquals(1234L, st.sentFinalSize.await())
                    assertEquals(1234L, ss.receivedFinalSize.await())
                    assertEquals(1234L, ss.receivedOffset.value)
                    assertEquals(1234L, st.sendReleased.value)
                    assertFailsWith<QuicException.ConnectionLost> { st.receivedFinalSize.await() }
                    assertFailsWith<QuicException.ConnectionLost> { ss.sentFinalSize.await() }
                    Unit
                }
            }
        }
}
