// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
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
                    val buf = ByteArray(1)
                    ss.input.readAvailable(buf, 0, 1)
                    st.reset(9)
                    val sent = assertNotNull(st.sentFinalSize).await()
                    assertEquals(sent, assertNotNull(ss.receivedFinalSize).await())
                    assertTrue(sent in 1L..3000L, "$sent")
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
                    // the receiver stops before reading: the answering RESET_STREAM still tells it how much the sender used
                    ss.stopSending(3)
                    val got = assertNotNull(ss.receivedFinalSize).await()
                    assertEquals(assertNotNull(st.sentFinalSize).await(), got)
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
                    st.resetAt(5, 10)
                    val ss = s.acceptStream()
                    val sent = assertNotNull(st.sentFinalSize).await()
                    assertEquals(sent, assertNotNull(ss.receivedFinalSize).await())
                    assertTrue(sent >= 10, "$sent")
                    c.close()
                    s.close()
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
