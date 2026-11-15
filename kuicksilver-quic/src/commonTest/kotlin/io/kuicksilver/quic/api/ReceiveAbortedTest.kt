// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.receiveAborted
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.seconds

/**
 * `QuicStream.receiveAborted`: completes with the peer's RESET_STREAM, never with a FIN, so a waiter tells an aborted
 * stream from a finished one exactly (a final size alone does not: both a FIN and a reset fix one). A rejected 0-RTT's
 * drop completes it too: `ZeroRttApiTest.rejectedZeroRttFailsEarlyStreamsAndTheConnectionGoesOn`.
 */
class ReceiveAbortedTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun aResetCompletesItWithTheReset() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(10), 0, 10)
                    st.output.flush()
                    val ss = s.acceptStream()
                    val aborted = assertNotNull(ss.receiveAborted) // made before the reset: the loop completes it
                    st.reset(9)
                    val e = assertIs<QuicException.StreamError.Reset>(aborted.await())
                    assertEquals(9L, e.code)
                    c.close()
                    s.close()
                }
            }
        }

    /** Asked for after the reset was processed: the cause is already there. */
    @Test fun aResetBeforeTheQuestionIsSeenToo() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(10), 0, 10)
                    st.output.flush()
                    val ss = s.acceptStream()
                    st.reset(7)
                    assertNotNull(ss.receivedFinalSize).await()
                    assertEquals(7L, assertIs<QuicException.StreamError.Reset>(assertNotNull(ss.receiveAborted).await()).code)
                    c.close()
                    s.close()
                }
            }
        }

    /** A FIN fixes the final size but is no abort; the connection's end is none either. Our own uni stream has none. */
    @Test fun negative_aFinIsNoAbort() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(10), 0, 10)
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    assertEquals(10L, assertNotNull(ss.receivedFinalSize).await())
                    val aborted = assertNotNull(ss.receiveAborted)
                    assertFalse(aborted.isCompleted)
                    assertNull(c.openUni().receiveAborted)
                    c.close()
                    s.close()
                    s.closed.await()
                    assertFalse(aborted.isCompleted)
                }
            }
        }
}
