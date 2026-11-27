// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.close
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.TimeoutKind
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.ConnectionRuntime
import io.kuicksilver.quic.runtime.KslRandom
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
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

    /**
     * `QuicEndpoint.close()` is asynchronous (its KDoc): the loop sends each connection's CONNECTION_CLOSE first and ends the
     * connection's application side right after (EndpointLoop.flushBody), so the peer may learn of the close before the
     * server's own `closed` completes. The server side is awaited, not sampled; its reason is the close it sent.
     */
    @Test fun endpointCloseSendsConnectionCloseToPeers() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    p.server.close()
                    val r = c.closed.await()
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(
                        r,
                        "the peer learns about the close at once, not by idle timeout: $r",
                    )
                    assertEquals(Initiator.Peer, r.initiator)
                    assertEquals(0L, r.code)
                    assertServerClosedByEndpoint(s.closed.await())
                }
            }
        }

    /**
     * The order the test above must allow, built deterministically (CI's API 24 emulator hit it by scheduling): the server's
     * CONNECTION_CLOSE reaches the client and the client's `closed` completes while the server's loop is still inside the
     * send, before it ends the server connection's application side. The server's `closed` completes after that, with
     * the reason of the close it sent.
     */
    @Test fun peerMayLearnOfAnEndpointCloseBeforeTheServerApplicationDoes() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val serverAddr = p.server.localAddress
                    val clientAddr = p.client.localAddress
                    // set and read on the server's loop only, inside its send
                    var held = false
                    var clientClosedFirst: QuicException.ConnectionLost? = null
                    var serverDoneThen = true
                    p.net.lose = lose@{ from, to, bytes ->
                        // the first datagram the closing server connection sends: delivered here, then the send is held until
                        // the client has taken it and completed its `closed`
                        if (held || from != serverAddr || to != clientAddr || s.core.state != ConnectionState.Closing) {
                            return@lose false
                        }
                        held = true
                        p.net.lose = null
                        p.net.deliver(from, to, bytes)
                        clientClosedFirst = runBlocking { withTimeoutOrNull(10.seconds) { c.closed.await() } }
                        serverDoneThen = s.closed.isCompleted
                        true // delivered above
                    }
                    p.server.close()
                    val sr = s.closed.await()
                    val r = assertIs<QuicException.ConnectionLost.ApplicationClosed>(c.closed.await())
                    assertTrue(held, "the server's CONNECTION_CLOSE went through the hook")
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(clientClosedFirst, "the client closed while the send was held")
                    assertEquals(Initiator.Peer, r.initiator)
                    assertFalse(serverDoneThen, "precondition: the server's `closed` was still open when the client's completed")
                    assertServerClosedByEndpoint(sr)
                }
            }
        }

    /** Makes the server side of [s]'s connection throw out of its next datagram; set on the loop that reads it. */
    private suspend fun armServerFailure(s: QuicConnection) =
        withContext((s as ConnectionRuntime).loopDispatcherForTest) { s.core.testInjectFailure = IllegalStateException("boom") }

    private fun assertServerClosedByEndpoint(sr: QuicException.ConnectionLost) {
        assertIs<QuicException.ConnectionLost.ApplicationClosed>(sr, "the server connection ends with the close it sent: $sr")
        assertEquals(Initiator.Local, sr.initiator)
        assertEquals(0L, sr.code)
    }

    @Test fun oneConnectionsInternalErrorLeavesTheOthersRunning() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c1, s1) = p.connect()
                    val (c2, s2) = p.connect()
                    // the stream is opened before the failure is armed: once armed, any client packet fails connection 1, also the
                    // client's late ACK of the server's post-handshake flight, and the reset a later one draws would make a later
                    // openBidi throw (openAfterTheServerForgotTheConnectionThrowsTheReset)
                    val st = c1.openBidi()
                    // the server side of connection 1 throws out of its next datagram
                    armServerFailure(s1)
                    // the server forgot connection 1 silently, so it answers the client's next packets with a Stateless Reset
                    // (RFC 9000 section 10.3): the write (a stream already closed by it) or this flush may already see connection 1
                    // reset, which is connection 1's fate, not 2's
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    }.exceptionOrNull()?.let {
                        assertIs<QuicException.ConnectionLost.StatelessReset>(c1.closed.await(), "write or flush failed with $it")
                    }
                    val r = withTimeoutOrNull(10.seconds) { s1.closed.await() }
                    assertIs<QuicException.ConnectionLost.Internal>(r, "connection 1 failed internally: $r")
                    val r1 = withTimeoutOrNull(10.seconds) { c1.closed.await() }
                    assertIs<QuicException.ConnectionLost.StatelessReset>(r1, "the client of connection 1 is reset: $r1")
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

    /**
     * The order the test above allows: the client of the failed connection can be reset (RFC 9000 section 10.3) before its
     * flush returns, and the flush then fails with that reset; the other connection is untouched.
     */
    @Test fun clientOfAFailedConnectionIsResetAndItsFlushMayFail() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c1, s1) = p.connect()
                    val (c2, s2) = p.connect()
                    val st = c1.openBidi() // before the arming, as in the test above
                    armServerFailure(s1)
                    // the datagram that makes the server fail connection 1; the write or the flush may already see the reset
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    }.exceptionOrNull()?.let {
                        assertIs<QuicException.ConnectionLost.StatelessReset>(c1.closed.await(), "write or flush failed with $it")
                    }
                    assertIs<QuicException.ConnectionLost.StatelessReset>(c1.closed.await())
                    // the write side reports the reset itself or a ClosedWriteChannelException caused (possibly through a copy) by it
                    val e =
                        kotlin.test.assertFails {
                            st.output.writeFully(byteArrayOf(2), 0, 1)
                            st.output.flush()
                        }
                    val chain = generateSequence(e) { it.cause }.toList()
                    assertTrue(chain.any { it is QuicException.ConnectionLost.StatelessReset }, "$chain")
                    assertFalse(c2.closed.isCompleted)
                    assertFalse(s2.closed.isCompleted)
                    c2.close()
                }
            }
        }

    /**
     * The interleaving the two tests above avoid by opening their stream first, forced: with the failure armed, a client
     * packet that is not ours to wait for (here a PING; on a slow runner the late ACK of the server's post-handshake flight)
     * fails the server's connection 1, the next one draws a Stateless Reset (RFC 9000 section 10.3), and a stream asked for
     * after it gets the connection's reason (QuicConnection.openBidi).
     */
    @Test fun openAfterTheServerForgotTheConnectionThrowsTheReset() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c1, s1) = p.connect()
                    val (c2, s2) = p.connect()
                    armServerFailure(s1)
                    c1.ping() // false when the late ACK already drew the reset
                    assertIs<QuicException.ConnectionLost.Internal>(s1.closed.await())
                    c1.ping()
                    val r = c1.closed.await()
                    assertIs<QuicException.ConnectionLost.StatelessReset>(r)
                    for (e in listOf(assertFailsWith<QuicException.ConnectionLost> { c1.openBidi() }, assertFailsWith { c1.openUni() })) {
                        assertIs<QuicException.ConnectionLost.StatelessReset>(e)
                        assertEquals(r.message, e.message)
                    }
                    assertFalse(c2.closed.isCompleted)
                    assertFalse(s2.closed.isCompleted)
                    c2.close()
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
