// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.close
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.KslRandom
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class QuicApiTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun keyUpdateSuspendsUntilConfirmedThenUpdates() =
        runBlocking {
            ApiPair.open(crypto = io.kuicksilver.tls.KslQuicCrypto).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    c.keyUpdate()
                    assertEquals(1L, c.stats.keyUpdates)
                    val echo =
                        async {
                            val st = s.acceptStream()
                            st.input.readExactly(3)
                        }
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1, 2, 3), 0, 3)
                    st.output.flush()
                    assertContentEquals(byteArrayOf(1, 2, 3), echo.await())
                    c.keyUpdate()
                    assertEquals(2L, c.stats.keyUpdates, "a second update once the first phase was acknowledged")
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun openedStreamReportsItsPriority() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, _) = p.connect()
                    assertEquals(StreamPriority(1, true), c.openBidi(StreamPriority(1, true)).priority)
                    assertEquals(StreamPriority(5), c.openUni(StreamPriority(5)).priority)
                }
            }
        }

    @Test fun echoBidiOneMiB() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val data = ByteArray(1 shl 20) { (it * 13).toByte() }
                    val echo =
                        async {
                            val st = s.acceptStream()
                            val got = st.input.readExactly(data.size)
                            st.output.writeFully(got, 0, got.size)
                            st.output.flushAndClose()
                            got.size
                        }
                    val st = c.openBidi()
                    st.output.writeFully(data, 0, data.size)
                    st.output.flushAndClose()
                    assertContentEquals(data, st.input.readExactly(data.size))
                    assertEquals(data.size, echo.await())
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun uniStreamFromServer() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val uni = s.openUni()
                    uni.output.writeFully(byteArrayOf(1, 2, 3), 0, 3)
                    uni.output.flushAndClose()
                    val got = c.acceptStream()
                    assertEquals(3L, got.id and 0x3L)
                    assertContentEquals(byteArrayOf(1, 2, 3), got.input.readExactly(3))
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun acceptStreamInOrder() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val ids =
                        (0 until 5).map {
                            c
                                .openBidi()
                                .also { st ->
                                    st.output.writeFully(byteArrayOf(it.toByte()), 0, 1)
                                    st.output.flush()
                                }.id
                        }
                    val seen = (0 until 5).map { s.acceptStream().id }
                    assertEquals(ids.sorted(), seen)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun openBidiSuspendsAtMaxStreamsAndResumes() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxBidiStreams = 2 }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val a = c.openBidi()
                    val b = c.openBidi()
                    for (st in listOf(a, b)) {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    }
                    val third = async { c.openBidi() }
                    delay(300)
                    assertFalse(third.isCompleted, "third stream waits for MAX_STREAMS")
                    val sa = s.acceptStream()
                    sa.input.readExactly(1)
                    sa.output.flushAndClose()
                    a.output.flushAndClose()
                    a.input.readExactly(0)
                    assertTrue(a.input.readAvailable(ByteArray(1), 0, 1) < 0)
                    // the server reads to EOF too: a stream counts as closed only once both halves are consumed (RFC 9000 sections 3.3,
                    // 4.6)
                    assertTrue(sa.input.readAvailable(ByteArray(1), 0, 1) < 0)
                    val t =
                        try {
                            third.await()
                        } catch (
                            e: Throwable,
                        ) {
                            throw AssertionError(
                                "third openBidi failed: $e; connection closed=${if (c.closed.isCompleted) c.closed.await() else null}",
                                e,
                            )
                        }
                    assertTrue(t.id > b.id)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun closedCompletesWithApplicationClosedLocal() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    c.close(42, "done")
                    val r = c.closed.await()
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(r)
                    assertEquals(42L, r.code)
                    assertEquals(Initiator.Local, r.initiator)
                    val sr = s.closed.await()
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(sr)
                    assertEquals(Initiator.Peer, sr.initiator)
                }
            }
        }

    @Test fun connectAfterEndpointCloseThrowsEndpointClosing() =
        runBlocking {
            val p = ApiPair.open()
            p.client.close()
            assertFailsWith<QuicException.EndpointClosing> {
                p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
            }
            p.server.close()
        }

    @Test fun handshakeTimeoutSurfacesTimeoutHandshake() =
        runBlocking {
            ApiPair.open(serverAnswers = false).use { p ->
                val e =
                    assertFailsWith<QuicException.ConnectionLost.Timeout> {
                        withTimeout(10.seconds) {
                            p.client.connect(
                                p.server.localAddress,
                                QuicClientConfig
                                    .Builder(CoreFixtures.client())
                                    .apply {
                                        quic =
                                            quicConfig { handshakeTimeout = 500.milliseconds }
                                    }.build(),
                            )
                        }
                    }
                assertEquals(TimeoutKind.Handshake, e.kind)
                assertEquals(500.milliseconds, e.duration)
            }
        }

    @Test fun runtimeRandomIsKslBacked() {
        val a = ByteArray(32)
        KslRandom.nextBytes(a)
        val b = ByteArray(32)
        KslRandom.nextBytes(b)
        assertTrue(
            a.any {
                it.toInt() !=
                    0
            },
        )
        assertFalse(a.contentEquals(b))
        assertTrue(KslRandom.nextLong() != KslRandom.nextLong())
    }

    // ---- final review fix pass ----
    @Test fun fortyConcurrentConnectionsAreAccepted() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    // the accept queue is drained by the loop; only connections the application has not accepted count (final review, Critical 1)
                    val pairs = (1..40).map { p.connect() }
                    assertEquals(40, pairs.size)
                    for ((c, s) in pairs) {
                        assertFalse(c.closed.isCompleted)
                        assertFalse(s.closed.isCompleted)
                    }
                    for ((c, s) in pairs) {
                        c.close()
                        s.close()
                    }
                }
            }
        }

    @Test fun endpointCloseSendsConnectionCloseToPeers() =
        runBlocking {
            val p = ApiPair.open()
            withTimeout(20.seconds) {
                val (c, s) = p.connect()
                p.server.close()
                val r = c.closed.await()
                assertIs<QuicException.ConnectionLost.ApplicationClosed>(
                    r,
                    "the peer learns about the close at once, not by idle timeout: $r",
                )
                assertEquals(Initiator.Peer, r.initiator)
                assertTrue(s.closed.isCompleted)
                p.client.close()
            }
        }

    @Test fun oneConnectionsInternalErrorLeavesTheOthersRunning() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c1, s1) = p.connect()
                    val (c2, s2) = p.connect()
                    // the server side of connection 1 throws out of its next datagram
                    s1.core.testInjectFailure = IllegalStateException("boom")
                    val st = c1.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush()
                    val r = withTimeoutOrNull(10.seconds) { s1.closed.await() }
                    assertIs<QuicException.ConnectionLost.Internal>(r, "connection 1 failed internally: $r")
                    val echo =
                        async {
                            val a = s2.acceptStream()
                            a.input.readExactly(3)
                        }
                    val st2 = c2.openBidi()
                    st2.output.writeFully(byteArrayOf(7, 8, 9), 0, 3)
                    st2.output.flush()
                    assertContentEquals(byteArrayOf(7, 8, 9), echo.await())
                    assertFalse(s2.closed.isCompleted)
                    c2.close()
                    s2.close()
                }
            }
        }

    @Test fun finishedStreamsReleaseTheirWrappers() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val rt = c as io.kuicksilver.quic.runtime.ConnectionRuntime
                    val srt = s as io.kuicksilver.quic.runtime.ConnectionRuntime
                    repeat(5) {
                        val st = c.openBidi()
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flushAndClose()
                        val sa = s.acceptStream()
                        sa.input.readExactly(1)
                        assertTrue(sa.input.readAvailable(ByteArray(1), 0, 1) < 0)
                        sa.output.flushAndClose()
                        assertTrue(st.input.readAvailable(ByteArray(1), 0, 1) < 0)
                    }
                    withTimeoutOrNull(5.seconds) { while (rt.streamCountForTest > 0 || srt.streamCountForTest > 0) delay(20) }
                    val diag = "client wrappers ${rt.streamIdsForTest} open-in-core=${rt.streamIdsForTest.map {
                        rt.core.isStreamOpenForTest(
                            it,
                        )
                    }} stats=${rt.core.stats}; server ${srt.streamIdsForTest}"
                    assertEquals(0, rt.streamCountForTest, "client wrappers released: $diag")
                    assertEquals(0, srt.streamCountForTest, "server wrappers released: $diag")
                    assertEquals(0, rt.tickerCountForTest)
                    assertEquals(0, srt.tickerCountForTest)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun exporterMatchesOnBothSides() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    assertContentEquals(
                        c.exportKeyingMaterial("EXPORTER-test", byteArrayOf(1), 32),
                        s.exportKeyingMaterial("EXPORTER-test", byteArrayOf(1), 32),
                    )
                    c.peerCertificates
                    // cached on the loop at handshake completion: no native call off the loop (the Null provider presents no chain)
                    s.peerCertificates
                    c.close()
                    s.close()
                }
            }
        }
}
