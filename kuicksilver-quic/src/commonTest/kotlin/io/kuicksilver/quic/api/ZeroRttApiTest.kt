// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.awaitSendStopped
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.receiveAborted
import io.kuicksilver.quic.runtime.ConnectionRuntime
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** 0-RTT through the public runtime API (ADR-0015): tickets kept per endpoint, connectEarly, early accept on the server. */
@OptIn(ExperimentalKuicksilverApi::class)
class ZeroRttApiTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun clientConfig(
        mode: EarlyDataState = EarlyDataState.Allowed,
        quic: io.kuicksilver.quic.QuicConfig = io.kuicksilver.quic.QuicConfig.Default,
    ) = QuicClientConfig
        .Builder(CoreFixtures.client())
        .apply {
            earlyData = mode
            this.quic = quic
        }.build()

    private suspend fun QuicConnection.echo(text: String): String {
        val s = openBidi()
        s.output.writeFully(text.encodeToByteArray())
        s.output.flushAndClose()
        return s.input.readAll()
    }

    private suspend fun io.ktor.utils.io.ByteReadChannel.readAll(): String {
        val b = ByteArray(4096)
        var out = ""
        while (true) {
            val n = readAvailable(b, 0, b.size)
            if (n < 0) return out
            out += b.decodeToString(0, n)
        }
    }

    /** A first connection that leaves the client a ticket for [p]'s server. */
    private suspend fun ticketFrom(
        p: ApiPair,
        quic: io.kuicksilver.quic.QuicConfig = io.kuicksilver.quic.QuicConfig.Default,
    ) {
        coroutineScope {
            val served =
                async {
                    val c = p.server.accept()
                    val s = c.acceptStream()
                    s.output.writeFully(s.input.readAll().encodeToByteArray())
                    s.output.flushAndClose()
                }
            val first = p.client.connect(p.server.localAddress, clientConfig(quic = quic))
            assertEquals("one", first.echo("one"))
            val sessions = (p.client as EndpointLoop).sessions
            while (sessions.size() == 0) yield()
            first.close()
            served.await()
        }
    }

    /**
     * A uni stream sent and reset in 0-RTT, before the server's answer: done on our side at once, its final size stands
     * only once the server accepted, and then both sides agree on it. RESET_STREAM_AT keeping all 5 bytes makes the size
     * exact whatever left before the reset.
     */
    @Test fun earlyStreamResetBeforeTheAnswerHasItsSizeOnAccept(): Unit = earlyResetAccepted(admission = null)

    /** The same through a Retry (RFC 9000 section 17.2.5): the 0-RTT that follows it is accepted, the size is exact. */
    @Test fun earlyStreamResetThroughARetryHasItsSize(): Unit =
        earlyResetAccepted(admission = io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry)

    private val withAt = quicConfig { resetStreamAt = true }

    private fun earlyResetAccepted(admission: io.kuicksilver.quic.ConnectionAdmission?): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true, admission = admission, serverQuic = withAt).use { p ->
                withTimeout(20.seconds) {
                    ticketFrom(p, withAt)
                    val peerSize =
                        async {
                            val c = p.server.accept()
                            c.acceptStream().receivedFinalSize!!.await() to c.earlyDataAccepted
                        }
                    p.net.hold(p.clientIo.localAddress)
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig(quic = withAt))
                    val st = second.openUni()
                    st.output.writeFully("early".encodeToByteArray())
                    st.output.flush()
                    st.resetAt(4, 5)
                    p.net.release(p.clientIo.localAddress)
                    second.awaitHandshake()
                    assertEquals(true, second.earlyDataAccepted)
                    assertEquals(5L, st.sentFinalSize!!.await())
                    assertEquals(5L to true, peerSize.await())
                    second.close()
                }
            }
        }

    /** Through a Retry to a server that refuses the ticket's early data: the stream fails, its size never stands. */
    @Test fun negative_earlyStreamResetThroughARetryThenARejectionFailsItsSize(): Unit =
        earlyResetRejected(io.kuicksilver.quic.ConnectionAdmission.AlwaysRetry)

    @Test fun negative_earlyStreamResetBeforeARejectionFailsItsSize(): Unit = earlyResetRejected(null)

    private fun earlyResetRejected(admission: io.kuicksilver.quic.ConnectionAdmission?): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    ticketFrom(p)
                    // a restarted server has other ticket keys: it refuses the ticket's early data
                    val server = p.restartServer(quicConfig { initialConnectionWindow = 700_000 }, KslQuicCrypto, admission = admission)
                    try {
                        launch { runCatching { server.accept() } } // ends with the server's close
                        p.net.hold(p.clientIo.localAddress)
                        val second = p.client.connectEarly(server.localAddress, clientConfig())
                        val st = second.openUni()
                        st.output.writeFully("early".encodeToByteArray())
                        st.output.flush()
                        st.reset(4)
                        p.net.release(p.clientIo.localAddress)
                        assertFailsWith<QuicException.StreamError.EarlyDataRejected> { st.sentFinalSize!!.await() }
                        second.awaitHandshake()
                        assertEquals(false, second.earlyDataAccepted)
                        second.close()
                    } finally {
                        server.close()
                    }
                }
            }
        }

    @Test fun negative_earlyStreamResetThenConnectionLossFailsItsSize(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    ticketFrom(p)
                    launch { runCatching { p.server.accept() } }
                    p.net.hold(p.clientIo.localAddress) // the answer never comes before the close
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig())
                    val st = second.openUni()
                    st.output.writeFully("early".encodeToByteArray())
                    st.output.flush()
                    st.reset(4)
                    second.close()
                    assertFailsWith<QuicException.ConnectionLost> { st.sentFinalSize!!.await() }
                    p.net.release(p.clientIo.localAddress)
                }
            }
        }

    @Test fun connectEarlySendsRequestIn0Rtt(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val earlyRequestRead = CompletableDeferred<Unit>()
                    val server =
                        async {
                            repeat(2) {
                                val c = p.server.accept()
                                val s = c.acceptStream()
                                val got = s.input.readAll()
                                val tag = "${c.earlyDataAccepted}/${s.receivedEarly}"
                                if (it == 1) earlyRequestRead.complete(Unit)
                                s.output.writeFully("$got:$tag".encodeToByteArray())
                                s.output.flushAndClose()
                            }
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one:null/false", first.echo("one"))
                    val sessions = (p.client as EndpointLoop).sessions
                    while (sessions.size() == 0) yield() // the ticket arrives after the handshake
                    first.close()
                    // the server's answers wait until it has read the whole request: a caller that resumes only after the
                    // handshake completed would rightly send it in 1-RTT (seen once on a loaded host), and the test is about 0-RTT
                    p.net.hold(p.clientIo.localAddress)
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig())
                    val s = second.openBidi()
                    s.output.writeFully("two".encodeToByteArray())
                    s.output.flushAndClose()
                    earlyRequestRead.await()
                    assertEquals(false, second.isHandshakeComplete, "the request was sent before the handshake completed")
                    p.net.release(p.clientIo.localAddress)
                    assertEquals("two:true/true", s.input.readAll(), "accepted early and answered")
                    second.awaitHandshake()
                    assertEquals(true, second.earlyDataAccepted)
                    server.await()
                }
            }
        }

    /** Every native key a 1-RTT and a 0-RTT connection made is freed by the time both endpoints closed (found by the soak harness). */
    @Test fun keysOfResumedConnectionsAreFreed(): Unit =
        runBlocking {
            for (early in listOf(false, true)) {
                val before = Ksl.liveObjects()[KslConst.LIVE_KEY]
                val p = ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true)
                withTimeout(20.seconds) {
                    val server =
                        async {
                            repeat(4) {
                                val c = p.server.accept()
                                val s = c.acceptStream()
                                val got = s.input.readAll()
                                s.output.writeFully(got.encodeToByteArray())
                                s.output.flushAndClose()
                                c.closed.await()
                            }
                        }
                    val sessions = (p.client as EndpointLoop).sessions
                    repeat(4) {
                        val c =
                            if (early) {
                                p.client.connectEarly(p.server.localAddress, clientConfig())
                            } else {
                                p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                            }
                        assertEquals("x$it", c.echo("x$it"))
                        c.awaitHandshake()
                        if (early) while (sessions.size() == 0) yield()
                        c.close()
                    }
                    server.await()
                }
                p.client.closeAndJoin()
                p.server.closeAndJoin()
                // other tests' endpoints may still be finishing their close (they only free keys): never more than before
                val after = Ksl.liveObjects()[KslConst.LIVE_KEY]
                assertTrue(
                    after <= before,
                    "native keys left after ${if (early) "0-RTT" else "1-RTT"} connections: $before before, $after after",
                )
            }
        }

    @Test fun streamsOpenedEarlyAndAfterTheHandshake(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val server =
                        async {
                            repeat(2) {
                                val c = p.server.accept()
                                repeat(if (it == 0) 1 else 2) {
                                    val s = c.acceptStream()
                                    if (s.id and 2L != 0L) {
                                        launch { s.input.readAll() } // the uni stream ends only after the echo
                                    } else {
                                        val got = s.input.readAll()
                                        s.output.writeFully("$got!".encodeToByteArray())
                                        s.output.flushAndClose()
                                    }
                                }
                            }
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one!", first.echo("one"))
                    val sessions = (p.client as EndpointLoop).sessions
                    while (sessions.size() == 0) yield()
                    first.close()
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig())
                    val u = second.openUni()
                    u.output.writeFully("control".encodeToByteArray())
                    u.output.flush()
                    second.awaitHandshake()
                    assertEquals("after!", second.echo("after"), "a stream opened after the handshake on a 0-RTT connection")
                    u.output.flushAndClose()
                    server.await()
                }
            }
        }

    /**
     * RFC 9001 section 4.6.2: the server restarted with another configuration and rejects the ticket's 0-RTT; the stream
     * opened early fails with [QuicException.StreamError.EarlyDataRejected] (the client "MUST reset the state of all
     * streams"), nothing of it reaches the server, and the connection serves a new stream.
     */
    @Test fun rejectedZeroRttFailsEarlyStreamsAndTheConnectionGoesOn(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val firstServer =
                        async {
                            val c = p.server.accept()
                            val s = c.acceptStream()
                            s.output.writeFully(s.input.readAll().encodeToByteArray())
                            s.output.flushAndClose()
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one", first.echo("one"))
                    val sessions = (p.client as EndpointLoop).sessions
                    while (sessions.size() == 0) yield()
                    first.close()
                    firstServer.await()
                    val server = p.restartServer(quicConfig { initialConnectionWindow = 700_000 }, KslQuicCrypto)
                    try {
                        val seen = mutableListOf<String>()
                        val serving =
                            async {
                                val c = server.accept()
                                val s = c.acceptStream()
                                val got = s.input.readAll()
                                seen += got
                                s.output.writeFully("$got!".encodeToByteArray())
                                s.output.flushAndClose()
                            }
                        // the server's answers wait until the early stream is written: it must leave in 0-RTT
                        p.net.hold(p.clientIo.localAddress)
                        val second = p.client.connectEarly(server.localAddress, clientConfig())
                        val early = second.openBidi()

                        // asked for before the rejection: the drop completes it (ReceiveAbortedTest has the reset and the FIN)
                        @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
                        val aborted = early.receiveAborted!!
                        early.output.writeFully("two".encodeToByteArray())
                        early.output.flushAndClose()
                        assertEquals(false, second.isHandshakeComplete)
                        p.net.release(p.clientIo.localAddress)
                        val e = assertFailsWith<QuicException.StreamError.EarlyDataRejected> { early.input.readAll() }
                        assertEquals(early.id, assertIs<QuicException.StreamError.EarlyDataRejected>(aborted.await()).streamId)
                        assertEquals(early.id, e.streamId)
                        // negative: the FIN left in 0-RTT, but the rejection dropped the stream, so its size never stood
                        @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                        assertFailsWith<QuicException.StreamError.EarlyDataRejected> { early.sentFinalSize!!.await() }
                        second.awaitHandshake()
                        assertEquals(false, second.earlyDataAccepted)
                        assertEquals("three!", second.echo("three"), "a new stream after the rejection")
                        serving.await()
                        assertEquals(listOf("three"), seen, "nothing of the rejected stream reached the server")
                        second.close()
                    } finally {
                        server.close()
                    }
                }
            }
        }

    /**
     * QC-1 (review 2026-10-28): the core drops the early streams and restarts their IDs while it handles the server's
     * flight; the runtime learns it when it drains the events, after the flush that follows. A flush stalled in a socket
     * send (a socket without room) parks the receive path in between. A stream opened in that window takes the
     * freed ID 0: it must get a wrapper of its own, not the early stream's, and a reset the application issues on the
     * early stream meanwhile must not reach the new one.
     */
    @Test fun streamOpenedBeforeTheRuntimeSawTheRejectionIsItsOwn(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val firstServer =
                        async {
                            val c = p.server.accept()
                            val s = c.acceptStream()
                            s.output.writeFully(s.input.readAll().encodeToByteArray())
                            s.output.flushAndClose()
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one", first.echo("one"))
                    val loop = p.client as EndpointLoop
                    while (loop.sessions.size() == 0) yield()
                    first.close()
                    firstServer.await()
                    val server = p.restartServer(quicConfig { initialConnectionWindow = 700_000 }, KslQuicCrypto)
                    try {
                        val seen = mutableListOf<String>()
                        val serving =
                            async {
                                val c = server.accept()
                                val s = c.acceptStream()
                                val got = s.input.readAll()
                                seen += got
                                s.output.writeFully("$got!".encodeToByteArray())
                                s.output.flushAndClose()
                            }
                        p.net.hold(p.clientIo.localAddress)
                        val second = p.client.connectEarly(server.localAddress, clientConfig()) as ConnectionRuntime
                        val early = second.openBidi()
                        early.output.writeFully("two".encodeToByteArray())
                        early.output.flushAndClose()
                        assertEquals(false, second.isHandshakeComplete)
                        // the flush that follows the core's rejection stalls in a send before it drains the events
                        val reached = CompletableDeferred<Unit>()
                        val gate = CompletableDeferred<Unit>()
                        p.clientIo.beforeSend = {
                            if (!reached.isCompleted && !second.core.streams.isOpen(early.id)) {
                                reached.complete(Unit)
                                gate.await()
                            }
                        }
                        p.net.release(p.clientIo.localAddress)
                        reached.await()
                        val opening = async { second.openBidi() }
                        // open() took the freed ID and now waits for the stalled flush
                        while (!withContext(second.loopDispatcherForTest) { second.core.streams.isOpen(early.id) }) yield()
                        early.reset(9) // the application gives the early stream up before it learnt of the rejection
                        withContext(second.loopDispatcherForTest) {} // the launched reset ran
                        p.clientIo.beforeSend = null
                        gate.complete(Unit)
                        val fresh = opening.await()
                        assertEquals(early.id, fresh.id, "the rejection freed the ID")
                        assertNotSame(early, fresh, "the new stream got the early stream's wrapper")
                        withContext(second.loopDispatcherForTest) {
                            assertSame<Any?>(fresh, second.streams[fresh.id], "the core's live stream has its wrapper")
                        }
                        assertFailsWith<QuicException.StreamError.EarlyDataRejected> { early.input.readAll() }
                        fresh.output.writeFully("three".encodeToByteArray())
                        fresh.output.flushAndClose()
                        assertEquals("three!", fresh.input.readAll(), "the early stream's reset reached the new stream")
                        serving.await()
                        assertEquals(listOf("three"), seen)
                        second.close()
                    } finally {
                        server.close()
                    }
                }
            }
        }

    /**
     * Found by the 0-RTT runtime invariant test. RFC 9001 section 4.6.2: the client "MUST reset the state of all streams,
     * including application state bound to those streams". A STOP_SENDING watcher (`awaitSendStopped`, which HTTP/3 keeps on
     * each critical stream) on a stream the rejection dropped waited for the rest of the connection; it now ends with
     * [QuicException.StreamError.EarlyDataRejected].
     */
    @OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)
    @Test
    fun negative_sendStoppedWatcherOfARejectedStreamEnds(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    val firstServer =
                        async {
                            val c = p.server.accept()
                            val s = c.acceptStream()
                            s.output.writeFully(s.input.readAll().encodeToByteArray())
                            s.output.flushAndClose()
                        }
                    val first = p.client.connect(p.server.localAddress, clientConfig())
                    assertEquals("one", first.echo("one"))
                    val sessions = (p.client as EndpointLoop).sessions
                    while (sessions.size() == 0) yield()
                    first.close()
                    firstServer.await()
                    val server = p.restartServer(quicConfig { initialConnectionWindow = 700_000 }, KslQuicCrypto)
                    try {
                        p.net.hold(p.clientIo.localAddress)
                        val second = p.client.connectEarly(server.localAddress, clientConfig())
                        val early = second.openUni()
                        early.output.writeFully("control".encodeToByteArray())
                        early.output.flush()
                        val watcher = async { runCatching { early.awaitSendStopped() }.exceptionOrNull() }
                        p.net.release(p.clientIo.localAddress)
                        second.awaitHandshake()
                        assertEquals(false, second.earlyDataAccepted)
                        val e = withTimeoutOrNull(5.seconds) { watcher.await() }
                        assertIs<QuicException.StreamError.EarlyDataRejected>(e, "the watcher of the dropped stream ended")
                        assertTrue(second.closed.isActive, "the connection goes on")
                        second.close()
                    } finally {
                        server.close()
                    }
                }
            }
        }

    @Test fun requiredWithoutTicketFails(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    assertFailsWith<QuicException.ConnectionLost.ZeroRttRejected> {
                        p.client.connectEarly(p.server.localAddress, clientConfig(EarlyDataState.Required))
                    }
                }
            }
        }

    @Test fun earlyDataDisabledByDefault(): Unit =
        runBlocking {
            ApiPair.open(crypto = KslQuicCrypto).use { p ->
                withTimeout(20.seconds) {
                    val server = async { p.server.accept() }
                    val c = p.client.connectEarly(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    assertTrue(server.await().earlyDataAccepted == null && c.earlyDataAccepted == null)
                    assertEquals(0, (p.client as EndpointLoop).sessions.size(), "no tickets kept without the opt-in")
                }
            }
        }
}
