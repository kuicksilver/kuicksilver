// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * `QuicStream.sentFinalSize` and `receivedFinalSize` (RFC 9000 section 4.5): both sides learn the same final size of a half,
 * also when it was reset or stopped before its bytes were read, which a protocol counting data across streams needs
 * (draft-ietf-webtrans-http3-16 section 5.4).
 */
class FinalSizeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun finFixesTheFinalSizeOnBothSidesWithoutReading() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openUni()
                    st.output.writeFully(ByteArray(1234), 0, 1234)
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    // nothing read: the FIN alone tells the receiver
                    assertEquals(1234L, assertNotNull(ss.receivedFinalSize).await())
                    assertEquals(1234L, assertNotNull(st.sentFinalSize).await())
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun resetGivesBothSidesTheSameFinalSize() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(3000), 0, 3000)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readFully(3000) // every byte went out: the reset's final size is 3000
                    st.reset(9)
                    assertEquals(3000L, assertNotNull(st.sentFinalSize).await())
                    assertEquals(3000L, assertNotNull(ss.receivedFinalSize).await())
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun stopSendingStillTellsTheReceiverTheFinalSize() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(5000), 0, 5000)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readFully(5000)
                    // the receiver stops reading: the answering RESET_STREAM still tells it how much the sender used
                    ss.stopSending(3)
                    assertEquals(5000L, assertNotNull(ss.receivedFinalSize).await())
                    assertEquals(5000L, assertNotNull(st.sentFinalSize).await())
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun resetAtGivesBothSidesTheSameFinalSize() =
        runBlocking {
            val on = quicConfig { resetStreamAt = true }
            ApiPair.open(serverQuic = on).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect(on)
                    val st = c.openUni()
                    st.output.writeFully(ByteArray(40_000), 0, 40_000)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readFully(40_000)
                    st.resetAt(5, 10)
                    assertEquals(40_000L, assertNotNull(st.sentFinalSize).await())
                    assertEquals(40_000L, assertNotNull(ss.receivedFinalSize).await())
                    c.close()
                    s.close()
                }
            }
        }

    /** receivedOffset follows what arrived, read or not, and ends at the final size. */
    @Test fun receivedOffsetFollowsUnreadData() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openUni()
                    st.output.writeFully(ByteArray(3000), 0, 3000)
                    st.output.flush()
                    val ss = s.acceptStream()
                    assertEquals(3000L, assertNotNull(ss.receivedOffset).first { it == 3000L }) // nothing read
                    st.reset(1)
                    assertEquals(3000L, assertNotNull(ss.receivedFinalSize).await())
                    assertEquals(3000L, ss.receivedOffset!!.value)
                    assertEquals(0L, assertNotNull(st.receivedOffset).value)
                    c.close()
                    s.close()
                }
            }
        }

    /**
     * A stream opened for a caller cancelled as it is handed back is never lost: it is reset, so the peer, which counts it
     * opened once a later stream arrives, sees it end (and its credit comes back).
     */
    @Test fun negative_streamOpenedForACancelledCallerIsReset() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val rt = c as io.kuicksilver.quic.runtime.ConnectionRuntime
                    val caller = CompletableDeferred<kotlinx.coroutines.Job>()
                    rt.openedForTest = { kotlinx.coroutines.runBlocking { caller.await() }.cancel() }
                    val opening = async { c.openUni() }
                    caller.complete(opening)
                    assertFailsWith<kotlinx.coroutines.CancellationException> { opening.await() }
                    rt.openedForTest = null
                    // a later stream reveals the first to the peer: the first arrives reset
                    val later = c.openUni()
                    later.output.writeFully(ByteArray(1), 0, 1)
                    later.output.flushAndClose()
                    val first = s.acceptStream()
                    assertFailsWith<QuicException.StreamError.Reset> {
                        try {
                            first.input.readAvailable(ByteArray(1), 0, 1)
                        } catch (e: Throwable) {
                            throw generateSequence(e) { it.cause }.filterIsInstance<QuicException.StreamError.Reset>().firstOrNull() ?: e
                        }
                    }
                    c.close()
                    s.close()
                }
            }
        }

    /**
     * Nothing observed a stream while it ran (its Deferreds and flows are made by the first reader): read only after the
     * connections ended, it still tells what was fixed before the end, not the loss that came after.
     */
    @Test fun aFirstReadAfterTheEndStillTellsWhatWasFixedBefore() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openUni()
                    st.output.writeFully(ByteArray(1234), 0, 1234)
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    val read = ss.input.readBuffer()
                    assertEquals(1234, read.readByteArray().size)
                    c.close()
                    s.close()
                    assertEquals(1234L, assertNotNull(st.sentFinalSize).await())
                    assertEquals(1234L, assertNotNull(ss.receivedFinalSize).await())
                    assertEquals(1234L, assertNotNull(ss.receivedOffset).value)
                    assertFailsWith<IllegalStateException> { assertNotNull(st.receivedFinalSize).await() }
                    assertFailsWith<IllegalStateException> { assertNotNull(ss.sentFinalSize).await() }
                    Unit
                }
            }
        }

    @Test fun negative_aMissingHalfHasNoFinalSize() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openUni()
                    assertFailsWith<IllegalStateException> { assertNotNull(st.receivedFinalSize).await() }
                    st.output.writeFully(ByteArray(1), 0, 1)
                    st.output.flush()
                    val ss = s.acceptStream()
                    assertFailsWith<IllegalStateException> { assertNotNull(ss.sentFinalSize).await() }
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun negative_aLostConnectionFailsFinalSizesNeverKnown() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(ByteArray(10), 0, 10)
                    st.output.flush()
                    s.acceptStream()
                    c.close()
                    assertFailsWith<QuicException.ConnectionLost> { assertNotNull(st.sentFinalSize).await() }
                    assertFailsWith<QuicException.ConnectionLost> { assertNotNull(st.receivedFinalSize).await() }
                    s.close()
                }
            }
        }
}

private suspend fun io.ktor.utils.io.ByteReadChannel.readFully(n: Int) {
    readByteArray(n)
}
