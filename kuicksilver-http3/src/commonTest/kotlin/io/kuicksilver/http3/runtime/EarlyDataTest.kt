// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Settings
import io.kuicksilver.http3.MemoryNet
import io.kuicksilver.http3.TestCerts
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.SessionTicketConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** HTTP/3 over 0-RTT (RFC 8470, RFC 9114 section 7.2.4.2, ADR-0015): early safe requests, gated unsafe ones, 425 and replay. */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class)
class EarlyDataTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Seen(
        val method: String,
        val early: Boolean,
        val handshakeDone: Boolean,
    )

    private class Fixture(
        policy: Http3EarlyDataPolicy,
    ) : AutoCloseable {
        val net = MemoryNet()
        private val a = net.open(InetSocketAddress("10.0.0.1", 1111))
        private val b = net.open(InetSocketAddress("10.0.0.2", 443))

        @kotlin.concurrent.Volatile var last: Seen? = null
        val executions = AtomicInt(0)

        /** Server connections in accept order (one writer, the accept loop). */
        @kotlin.concurrent.Volatile var accepted: List<Http3Connection> = emptyList()

        /** Requests that came in 0-RTT and the server's gate held for the handshake (RFC 8470), over all connections. */
        val heldEarly: Int get() = accepted.sumOf { it.session.earlyHeldForHandshake.load() }

        // accept()/acceptRequest() end with an exception when the endpoint or a connection closes: on Kotlin/Native an
        // unhandled one would end the test process
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + kotlinx.coroutines.CoroutineExceptionHandler { _, _ -> })
        lateinit var server: Http3Endpoint
        lateinit var client: Http3Endpoint
        val serverSettings: Http3Settings = http3Settings { earlyData = policy }

        suspend fun start() {
            server =
                Http3Endpoint.bind(
                    b.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(H3Fixtures.server()).apply { earlyData = true }.build()
                            crypto = KslQuicCrypto
                            io = { b }
                        }.build(),
                    serverSettings,
                )
            client =
                Http3Endpoint.bind(
                    a.localAddress,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            crypto = KslQuicCrypto
                            io = { a }
                        }.build(),
                )
            scope.launch {
                while (true) {
                    val c = server.accept()
                    accepted = accepted + c
                    scope.launch {
                        // each connection on its own: a closed one must not end the accept loop
                        while (true) {
                            val r = c.acceptRequest()
                            scope.launch {
                                r.body.readAllBytes()
                                if (r.method == "POST") executions.incrementAndFetch()
                                last = Seen(r.method, r.receivedEarly, c.quic.isHandshakeComplete)
                                r.respond(200, Http3Headers.Empty).also {
                                    it.output.writeFully("${r.method} ok".encodeToByteArray())
                                    it.finish()
                                }
                            }
                        }
                    }
                }
            }
        }

        /** A first connection that leaves the client endpoint a ticket. */
        suspend fun warmUp() {
            val c = client.connectEarly(server.localAddress, H3Fixtures.client())
            repeat(2) { assertEquals(200, c.request(get()).also { it.body.readAllBytes() }.status) }
            c.close()
        }

        fun get(early: Boolean = false) =
            http3Request("GET", "server.test", "/") {
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                allowEarlyData = early
            }

        fun post() = http3Request("POST", "server.test", "/order")

        override fun close() {
            scope.cancel()
            client.close()
            server.close()
        }
    }

    /**
     * RFC 9297 section 2.1.1: a server "MUST NOT reduce" SETTINGS_H3_DATAGRAM for 0-RTT. The setting is bound into the
     * ticket's early-data context: a ticket from a server with H3_DATAGRAM=1 gives no 0-RTT to one (sharing its ticket
     * keys) that now sends 0, while the same settings accept it.
     */
    @Test fun h3DatagramChangeInvalidatesEarlyData(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                for ((resumerDatagrams, expected) in listOf(true to true, false to false)) {
                    assertEquals(
                        expected,
                        earlyAcceptedAfterResuming(
                            issuer = http3Settings {},
                            resumer =
                                http3Settings {
                                    h3Datagram =
                                        resumerDatagrams
                                },
                        ),
                    )
                }
            }
        }

    /** A client gets a ticket from a server with [issuer] settings, then resumes with 0-RTT at another with [resumer] and the same ticket keys. */
    private suspend fun earlyAcceptedAfterResuming(
        issuer: Http3Settings,
        resumer: Http3Settings,
        earlyRequest: Boolean = false,
        resumerRequests: AtomicInt = AtomicInt(0),
        clientSettings: Http3Settings = Http3Settings.Default,
        responseHeaders: Http3Headers = Http3Headers.Empty,
        /**
         * Runs right after `connectEarly`, while the network holds the server's answers back (the client is in 0-RTT), with
         * a function that lets them through; they go through when it returns at the latest.
         */
        beforeRequest: (suspend (Http3Connection, () -> Unit) -> Unit)? = null,
        /** Sees the client's socket. */
        clientIo: (io.kuicksilver.http3.MemoryIo) -> Unit = {},
        /** 1 while the network holds the server's answers to the resuming client back (the client stays in 0-RTT); the test lets them go. */
        clientHold: AtomicInt? = null,
        /** Sees the resuming client's HTTP/3 session before it starts. */
        clientSession: ((H3Session) -> Unit)? = null,
        /** false: the test ends the connection in [beforeRequest]; no request follows and the result is null. */
        sendRequest: Boolean = true,
        /** Runs once the early request was answered, with the client connection and the resuming server's connections. */
        after: suspend (Http3Connection, () -> List<Http3Connection>) -> Unit = { _, _ -> },
    ): Boolean? {
        val net = MemoryNet()
        val a = net.open(InetSocketAddress("10.0.0.1", 1111))
        clientIo(a)
        val b1 = net.open(InetSocketAddress("10.0.0.2", 443))
        val b2 = net.open(InetSocketAddress("10.0.0.3", 443))
        val keys = SessionTicketConfig(keys = listOf(ByteArray(80) { 5 }))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default + kotlinx.coroutines.CoroutineExceptionHandler { _, _ -> })

        suspend fun server(
            io: io.kuicksilver.quic.DatagramIo,
            settings: Http3Settings,
        ) = Http3Endpoint.bind(
            io.localAddress,
            QuicEndpointConfig
                .Builder()
                .apply {
                    val tls =
                        tlsConfig(TlsRole.Server) {
                            alpn = listOf("h3")
                            identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                            sessionTickets = keys
                        }
                    this.server = QuicServerConfig.Builder(tls).apply { earlyData = true }.build()
                    crypto = KslQuicCrypto
                    this.io = { io }
                }.build(),
            settings,
        )
        val first = server(b1, issuer)
        val second = server(b2, resumer)
        val client =
            Http3Endpoint.bind(
                a.localAddress,
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        crypto = KslQuicCrypto
                        io = { a }
                    }.build(),
            )
        val resumed = kotlin.concurrent.atomics.AtomicReference<List<Http3Connection>>(emptyList())
        try {
            for (srv in listOf(first, second)) {
                scope.launch {
                    while (true) {
                        val c = srv.accept()
                        if (srv === second) resumed.store(resumed.load() + c)
                        scope.launch {
                            while (true) {
                                val r = c.acceptRequest()
                                if (srv === second) resumerRequests.incrementAndFetch()
                                scope.launch { r.respond(204, responseHeaders).finish() }
                            }
                        }
                    }
                }
            }
            val warm = client.connectEarly(first.localAddress, H3Fixtures.client())
            repeat(2) { assertEquals(204, warm.request(http3Request("GET", "server.test", "/")).status) } // the ticket arrives
            warm.close()
            val holding = clientHold ?: AtomicInt(if (beforeRequest != null) 1 else 0)
            net.drop = { _, to, _ -> holding.load() == 1 && to == a.localAddress }
            if (clientSession != null) H3Session.createdForTest = { if (!it.isServer) clientSession(it) }
            val c =
                try {
                    client.connectEarly(second.localAddress, H3Fixtures.client(), settings = clientSettings)
                } finally {
                    H3Session.createdForTest = null
                }
            beforeRequest?.invoke(c) { holding.store(0) }
            holding.store(0)
            if (!sendRequest) return null
            val request =
                http3Request("GET", "server.test", "/") {
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    allowEarlyData = earlyRequest
                }
            assertEquals(204, c.request(request).status)
            c.quic.awaitHandshake()
            after(c) { resumed.load() }
            return c.quic.earlyDataAccepted
        } finally {
            scope.cancel()
            client.close()
            first.close()
            second.close()
        }
    }

    /**
     * RFC 9001 section 4.6.2: a rejected 0-RTT resets every stream the client opened, so an early request is lost with it;
     * the client sends it again on a new stream after the handshake (a safe method, so repeating it is allowed: RFC 9110
     * section 9.2.2), once, and the caller gets the answer. The server sees the request exactly once.
     */
    @Test fun earlyRequestIsSentAgainAfterRejection(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val seen = AtomicInt(0)
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer = http3Settings {},
                        resumer = http3Settings { h3Datagram = false },
                        earlyRequest = true,
                        resumerRequests = seen,
                    )
                assertEquals(false, accepted)
                assertEquals(1, seen.load())
            }
        }

    /**
     * RFC 9114 section 7.2.4.2: "Endpoints MUST NOT require any data to be received from the peer prior to sending the
     * SETTINGS frame; settings MUST be sent as soon as the transport is ready to send data." In 0-RTT the transport is ready
     * at once: the server has the client's SETTINGS while the client still waits for the server's handshake flight, which
     * the network holds back here.
     */
    @Test fun clientSendsSettingsIn0Rtt(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(30.seconds) {
                    f.start()
                    f.warmUp()
                    val clientAddr = InetSocketAddress("10.0.0.1", 1111)
                    val holding = AtomicInt(1)
                    f.net.drop = { _, to, _ -> holding.load() == 1 && to == clientAddr }
                    val before = f.accepted.size
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    while (f.accepted.size == before) kotlinx.coroutines.yield() // accepted in 0-RTT
                    val s = f.accepted.last()
                    // a bound, not a wait: the client's handshake cannot complete while the network holds its flight back
                    val got = withTimeoutOrNull(10.seconds) { s.session.peerSettings.first { it != null } }
                    assertTrue(got != null, "the client's SETTINGS did not arrive while its handshake waited")
                    assertEquals(false, c.quic.isHandshakeComplete, "the client's SETTINGS went out before its handshake completed")
                    holding.store(0)
                    c.quic.awaitHandshake()
                    assertEquals(true, c.quic.earlyDataAccepted)
                    assertEquals(200, c.request(f.get()).also { it.body.readAllBytes() }.status)
                    c.close()
                }
            }
        }

    /**
     * RFC 9001 section 4.6.2: a rejected 0-RTT resets every stream the client opened, its control and QPACK streams too; it
     * opens them again and sends SETTINGS once more (RFC 9114 section 6.2.1: "Each side MUST initiate a single control stream
     * at the beginning of the connection and send its SETTINGS frame as the first frame on this stream"). Nothing of the early
     * streams reaches the server, a QPACK Stream Cancellation for the early request neither (RFC 9204 section 2.2.2.2: one
     * is for a stream whose field sections the decoder may still be owed; the server never saw this one, and the request
     * that is sent again reuses its stream ID, review 2026-10-28 H3C-1), and both dynamic tables work on the connection.
     */
    @Test fun rejectedZeroRttReopensTheControlAndQpackStreams(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val seen = AtomicInt(0)
                val dynamic = http3Settings { enableQpackDynamicTable() }
                val headers = Http3Headers.of("x-session-detail" to "a value worth putting into the dynamic table")
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer = http3Settings { enableQpackDynamicTable() },
                        resumer =
                            http3Settings {
                                enableQpackDynamicTable()
                                h3Datagram = false
                            },
                        earlyRequest = true,
                        resumerRequests = seen,
                        clientSettings = dynamic,
                        responseHeaders = headers,
                    ) { c, resumed ->
                        val s = resumed().single()
                        val ps = s.session.peerSettings.first { it != null }!!
                        assertEquals(4096L, ps.qpackMaxTableCapacity, "the client's SETTINGS reached the server")
                        repeat(3) {
                            val r = c.request(http3Request("GET", "server.test", "/again"))
                            assertEquals(204, r.status)
                            assertEquals("a value worth putting into the dynamic table", r.headers["x-session-detail"])
                        }
                        s.session.criticalStreamsSeen.first { it == 3 }
                        assertEquals(0L, s.session.qpack.peerStreamCancellations, "no Stream Cancellation for the early request")
                        withContext(c.session.dispatcher) {
                            // not merely dropped on the way: none was made for the stream the rejection dropped
                            assertEquals(
                                0L,
                                c.session.qpack.streamCancellationsMade,
                                "a Stream Cancellation was made for the early request",
                            )
                        }
                        assertTrue(s.session.qpack.encoderInserts > 0, "the server's encoder used the dynamic table")
                        assertTrue(!s.session.closed.isCompleted && !c.session.closed.isCompleted, "the connection lives")
                    }
                assertEquals(false, accepted)
                assertEquals(4, seen.load(), "the early request once, after the rejection, and three more")
            }
        }

    /**
     * Review 2026-10-28 N1: the rejection is known before the first attempt opens its critical streams, so they are 1-RTT
     * streams, and the client notes the rejection (the server's control stream arrives) while that attempt is between its
     * control stream and its QPACK streams. Nothing of the attempt was dropped, so it goes on: giving it up reset the typed
     * control stream, which the server must treat as H3_CLOSED_CRITICAL_STREAM (RFC 9114 section 6.2.1: "If either control
     * stream is closed at any point, this MUST be treated as a connection error of type H3_CLOSED_CRITICAL_STREAM").
     */
    @Test fun liveCriticalStreamsSurviveARejectionNotedWhileTheyAreSetUp(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val attempts = AtomicInt(0)
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer = http3Settings {},
                        resumer = http3Settings { h3Datagram = false },
                        clientSession = { session ->
                            session.criticalAttemptHookForTest = { step, _ ->
                                when (step) {
                                    H3Session.AttemptStep.Started -> {
                                        attempts.incrementAndFetch()
                                        runCatching { session.quic.awaitHandshake() } // the rejection came first
                                    }

                                    H3Session.AttemptStep.ControlWritten -> {
                                        // the server's control stream is taken meanwhile, and the rejection noted
                                        while (!session.zeroRttRejectionNotedForTest) kotlinx.coroutines.yield()
                                    }

                                    else -> {}
                                }
                            }
                        },
                    ) { c, resumed ->
                        val s = resumed().single()
                        repeat(2) { assertEquals(204, c.request(http3Request("GET", "server.test", "/again")).status) }
                        s.session.criticalStreamsSeen.first { it == 3 }
                        assertTrue(!s.session.closed.isCompleted && !c.session.closed.isCompleted, "the connection lives")
                    }
                assertEquals(false, accepted)
                assertEquals(1, attempts.load(), "the first attempt's streams were live: no second one")
            }
        }

    /**
     * An attempt that opened its critical streams in 0-RTT, which the rejection then dropped, gives up (its writes fail) and
     * a second attempt opens new ones and sends SETTINGS (RFC 9001 section 4.6.2; RFC 9114 section 6.2.1). The server sees
     * one set of critical streams.
     */
    @Test fun anAttemptTheRejectionInterruptsIsMadeAgain(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val attempts = AtomicInt(0)
                val hold = AtomicInt(1) // the client stays in 0-RTT until its first attempt opened its streams
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer = http3Settings {},
                        resumer = http3Settings { h3Datagram = false },
                        clientHold = hold,
                        clientSession = { session ->
                            session.criticalAttemptHookForTest = { step, gen ->
                                if (step == H3Session.AttemptStep.Started) attempts.incrementAndFetch()
                                // opened in 0-RTT; the rejection drops them before their type is written
                                if (step == H3Session.AttemptStep.Opened && gen == 0) {
                                    assertEquals(false, session.quic.isHandshakeComplete, "opened in 0-RTT")
                                    hold.store(0)
                                    runCatching { session.quic.awaitHandshake() }
                                }
                            }
                        },
                    ) { c, resumed ->
                        val s = resumed().single()
                        assertTrue(s.session.peerSettings.first { it != null } != null, "the client's SETTINGS reached the server")
                        assertEquals(204, c.request(http3Request("GET", "server.test", "/again")).status)
                        s.session.criticalStreamsSeen.first { it == 3 }
                        assertTrue(!s.session.closed.isCompleted && !c.session.closed.isCompleted, "the connection lives")
                    }
                assertEquals(false, accepted)
                assertEquals(2, attempts.load(), "the interrupted attempt and the one after it")
            }
        }

    /**
     * Control frames written in 0-RTT go with the dropped control stream; the new one carries those still wanted after
     * SETTINGS: a GOAWAY does, a PRIORITY_UPDATE for a request stream the rejection dropped does not (its ID names the next
     * request now).
     */
    @Test fun controlFramesOfTheDroppedControlStreamAreSentAgainWhenStillWanted(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer = http3Settings {},
                        resumer = http3Settings { h3Datagram = false },
                        beforeRequest = { c, _ ->
                            assertEquals(false, c.quic.isHandshakeComplete)
                            c.session.sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(8))
                            val early = c.quic.openBidi()
                            c.session.sendControl(FrameType.PRIORITY_UPDATE_REQUEST, ControlFrames.priorityUpdatePayload(early.id, "u=1")) {
                                !c.session.droppedByRejectedZeroRtt(early)
                            }
                        },
                    ) { _, resumed ->
                        val s = resumed().single()
                        s.session.goAwayReceived.first { it != null }
                        assertEquals(8L, s.session.goAwayReceived.value, "the GOAWAY went again on the new control stream")
                        withContext(s.session.dispatcher) {
                            assertEquals(0, s.session.priorityUpdatesForTest, "no PRIORITY_UPDATE for the dropped stream")
                        }
                    }
                assertEquals(false, accepted)
            }
        }

    /**
     * Review 2026-10-28 N2: the core dropped the critical streams, and the runtime has not reported the rejection yet (its
     * flush waits in a socket send). A control write meanwhile fails on the dropped stream; it waits for the handshake's end
     * instead of retrying at once, so the session's only thread stays free, and it ends once the connection does.
     */
    @Test fun aControlWriteInTheRejectionWindowWaitsInsteadOfSpinning(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val reached = kotlinx.coroutines.CompletableDeferred<Unit>()
                val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
                val conn = kotlin.concurrent.atomics.AtomicReference<Http3Connection?>(null)
                earlyAcceptedAfterResuming(
                    issuer = http3Settings {},
                    resumer = http3Settings { h3Datagram = false },
                    sendRequest = false,
                    clientIo = { io ->
                        io.beforeSend = {
                            val q = conn.load()?.quic
                            // the core completed the handshake, which reset the early streams of the rejected 0-RTT, and the runtime
                            // has not drained that yet: the window
                            val core = q?.core
                            if (!reached.isCompleted && core != null && core.earlyDataAccepted == false &&
                                core.state != ConnectionState.Handshaking && q.earlyDataAccepted == null
                            ) {
                                reached.complete(Unit)
                                gate.await()
                            }
                        }
                    },
                    beforeRequest = { c, release ->
                        conn.store(c)
                        release()
                        reached.await()
                        // still wanted on a new control stream, so a write that does not wait would retry at once: counted, and
                        // bounded so that such a spin ends the test instead of holding the session's thread for good
                        val retries = AtomicInt(0)
                        val write =
                            c.session.scope.launch {
                                runCatching {
                                    c.session.sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(8)) {
                                        retries.incrementAndFetch() <
                                            1000
                                    }
                                }
                            }
                        while (c.session.criticalWriteFailuresForTest.load() == 0) kotlinx.coroutines.yield() // it met the dropped stream
                        withTimeout(5.seconds) { withContext(c.session.dispatcher) { kotlinx.coroutines.yield() } }
                        assertEquals(0, retries.load(), "it retried on the failed stream instead of waiting for the handshake's end")
                        assertTrue(!write.isCompleted, "it waits for the handshake's end")
                        // the connection ends; its close waits behind the stalled flush, which reports the rejection and the
                        // handshake's end first: the write asks once whether the GOAWAY is still wanted on new streams, and then
                        // ends with the connection instead of waiting for streams that never come
                        c.quic.close()
                        gate.complete(Unit)
                        withTimeout(10.seconds) { write.join() }
                        assertEquals(1, retries.load(), "one try for the new control stream, after the handshake's end")
                    },
                ) { _, _ -> }
            }
        }

    /**
     * Review 2026-10-28 N3: the session's state is its dispatcher's alone. The early request sent again after the rejection
     * notes the rejection, and `updatePriority` writes on the control stream, from the caller's thread; both hop to the
     * session's dispatcher first (the hook fails the call otherwise).
     */
    @Test fun rejectionBookkeepingRunsOnTheSessionDispatcher(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer = http3Settings {},
                        resumer = http3Settings { h3Datagram = false },
                        earlyRequest = true,
                        clientSession = { it.assertOnDispatcherForTest = true },
                    ) { c, _ ->
                        val r = c.request(http3Request("GET", "server.test", "/again"))
                        assertEquals(204, r.status)
                        r.updatePriority(io.kuicksilver.quic.StreamPriority(urgency = 1, incremental = false)) // from this thread
                        assertTrue(!c.session.closed.isCompleted)
                    }
                assertEquals(false, accepted)
            }
        }

    @Test fun earlyGetIsAnsweredIn0Rtt(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds // a round trip the 0-RTT request can beat
                    val c: Http3Connection = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    val r = c.request(f.get(early = true))
                    assertEquals("GET ok", r.body.readAllBytes().decodeToString())
                    c.quic.awaitHandshake()
                    assertEquals(true, c.quic.earlyDataAccepted)
                    val last = f.last!!
                    assertTrue(last.early && !last.handshakeDone, "the server ran the safe request before the handshake completed")
                }
            }
        }

    @Test fun unsafeRequestWaitsForHandshakeOnTheClient(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    assertEquals(
                        "POST ok",
                        c
                            .request(f.post())
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                    val last = f.last!!
                    assertTrue(!last.early && last.handshakeDone, "a POST never leaves the client in 0-RTT")
                }
            }
        }

    @Test fun negative_unsafeMethodNotProcessedInEarlyData(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    c.session.testSendUnsafeEarly = true // a client that ignores RFC 8470: POST in 0-RTT
                    assertEquals(
                        "POST ok",
                        c
                            .request(f.post())
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                    c.quic.awaitHandshake()
                    assertEquals(true, c.quic.earlyDataAccepted, "the server accepted the 0-RTT that carried the POST")
                    assertEquals(1, f.heldEarly, "the POST arrived in 0-RTT and the gate held it")
                    val last = f.last!!
                    assertTrue(!last.early && last.handshakeDone, "the early POST ran only after the handshake")
                    assertEquals(1, f.executions.load())
                    c.close()

                    // The replay, stopped by the HTTP/3 gate alone: an attacker on the path keeps a client's datagrams from the
                    // server and sends copies from its own address, so the replay register sees the ticket for the first time
                    // and admits it; the server's answers go to the attacker, who cannot complete the handshake.
                    f.warmUp() // a fresh ticket for the victim
                    f.net.delay = kotlin.time.Duration.ZERO // delivered at once, in order
                    val attacker = InetSocketAddress("10.0.0.9", 9999)
                    val fromClient = { from: InetSocketAddress, to: InetSocketAddress -> to.port == 443 && from.port == 1111 }
                    // the victim's packets are all long-header (its handshake never completes): told apart by their DCID
                    val dcid = { b: ByteArray -> if (b[0].toInt() and 0x80 != 0) b.copyOfRange(6, 6 + b[5]) else null }
                    var victim: ByteArray? = null
                    val isVictim = { from: InetSocketAddress, to: InetSocketAddress, b: ByteArray ->
                        fromClient(from, to) && dcid(b)?.contentEquals(victim) == true
                    }
                    f.net.tap = { from, to, bytes ->
                        if (fromClient(from, to) && victim == null) victim = dcid(bytes)
                        if (isVictim(from, to, bytes)) f.net.deliver(attacker, to, bytes)
                    }
                    f.net.drop = isVictim
                    val v = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    v.session.testSendUnsafeEarly = true
                    val pending = f.scope.launch { v.request(f.post()) }
                    while (f.heldEarly < 2) kotlinx.coroutines.yield()
                    assertEquals(
                        true,
                        f.accepted
                            .last()
                            .quic.earlyDataAccepted,
                        "the register admitted the replay: only the gate is left",
                    )
                    // a later request on a new connection is processed after the replayed datagrams (one loop, FIFO)
                    val d = f.client.connect(f.server.localAddress, H3Fixtures.client())
                    assertEquals(
                        "POST ok",
                        d
                            .request(f.post())
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                    assertEquals(2, f.executions.load(), "the replayed POST never ran: its handshake cannot complete")
                    pending.cancel()
                    v.close()
                }
            }
        }

    @Test fun reject425PolicyAndOneRetry(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.Reject425()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    c.session.testSendUnsafeEarly = true
                    val r = c.request(f.post())
                    assertEquals(200, r.status)
                    assertEquals("POST ok", r.body.readAllBytes().decodeToString())
                    assertEquals(1, c.session.early425Retries, "425 Too Early, then one retry after the handshake")
                    assertEquals(1, f.executions.load())
                }
            }
        }
}
