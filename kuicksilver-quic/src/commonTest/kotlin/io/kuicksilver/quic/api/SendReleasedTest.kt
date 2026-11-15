// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * `QuicStream.sendReleased`: the bytes of a sending half the connection's shared send buffer let go of (acknowledged, or
 * dropped by a reset), which a protocol multiplexing independent users over one connection needs to share that buffer.
 */
class SendReleasedTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun acknowledgedBytesAreReleased() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    val released = assertNotNull(st.sendReleased)
                    st.output.writeFully(ByteArray(100_000), 0, 100_000)
                    st.output.flush()
                    s.acceptStream().input.readByteArray(100_000)
                    released.first { it == 100_000L }
                    c.close()
                    s.close()
                }
            }
        }

    /** Followed only after the bytes went out: the first read catches up with what was released before. */
    @Test fun aLateReaderCatchesUp() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openUni()
                    st.output.writeFully(ByteArray(50_000), 0, 50_000)
                    st.output.flushAndClose()
                    s.acceptStream().input.readByteArray(50_000)
                    assertNotNull(st.sentFinalSize).await()
                    assertNotNull(st.sendReleased).first { it == 50_000L }
                    c.close()
                    s.close()
                }
            }
        }

    /**
     * A peer that never reads holds the bytes beyond its stream window in our buffer: they stay unreleased (what a
     * per-user cap counts) until a reset drops them, which releases everything.
     */
    @Test fun negative_bytesAnUnreadStreamHoldsAreReleasedByItsReset() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { initialStreamWindow = 16_384 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    val released = assertNotNull(st.sendReleased)
                    st.output.writeFully(ByteArray(200_000), 0, 200_000)
                    st.output.flush()
                    s.acceptStream() // never read
                    // the window is all the peer takes: the rest stays buffered
                    assertNull(withTimeoutOrNull(300.milliseconds) { released.first { it > 16_384L } })
                    st.reset(1)
                    released.first { it == 200_000L }
                    c.close()
                    s.close()
                }
            }
        }

    /** The peer's STOP_SENDING drops what was buffered too. */
    @Test fun negative_stopSendingReleasesTheBuffer() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { initialStreamWindow = 16_384 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    val released = assertNotNull(st.sendReleased)
                    st.output.writeFully(ByteArray(100_000), 0, 100_000)
                    st.output.flush()
                    s.acceptStream().stopSending(3)
                    released.first { it == 100_000L }
                    c.close()
                    s.close()
                }
            }
        }

    /** The connection's end lets go of everything it held. */
    @Test fun negative_aLostConnectionReleasesEverything() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { initialStreamWindow = 16_384 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    val released = assertNotNull(st.sendReleased)
                    st.output.writeFully(ByteArray(100_000), 0, 100_000)
                    st.output.flush()
                    s.acceptStream()
                    c.close()
                    released.first { it == 100_000L }
                    s.close()
                }
            }
        }

    @Test fun thePeersUnidirectionalStreamReleasesNothing() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openUni()
                    st.output.writeFully(ByteArray(10), 0, 10)
                    st.output.flushAndClose()
                    val ss = s.acceptStream()
                    assertEquals(0L, assertNotNull(ss.sendReleased).value)
                    c.close()
                    s.close()
                }
            }
        }
}
