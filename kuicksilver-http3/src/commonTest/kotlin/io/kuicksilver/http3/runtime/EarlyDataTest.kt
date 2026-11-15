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
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.runtime.QuicStreamLimits
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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** HTTP/3 over 0-RTT (RFC 8470, RFC 9114 section 7.2.4.2, ADR-0015): early safe requests, gated unsafe ones, 425 and replay. */
@OptIn(ExperimentalKuicksilverApi::class, ExperimentalAtomicApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)
class EarlyDataTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Seen(
        val method: String,
        val early: Boolean,
        val handshakeDone: Boolean,
    )

    private class Fixture(
        policy: Http3EarlyDataPolicy,
        private val clientSettings: Http3Settings = Http3Settings.Default,
        /** Handles the server's CONNECT requests instead of the echo (which reads the body first). */
        private val onConnect: (suspend (io.kuicksilver.http3.Http3ServerRequest, Http3Connection) -> Unit)? = null,
        settings: Http3Settings.Builder.() -> Unit = {},
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
        val serverSettings: Http3Settings =
            http3Settings {
                earlyData = policy
                settings()
            }

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
                                if (r.method == "CONNECT" && onConnect != null) return@launch onConnect(r, c)
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

        /** A first connection that leaves the client endpoint a ticket (with the server's SETTINGS kept in it). */
        suspend fun warmUp() {
            val c = connectEarly()
            repeat(2) { assertEquals(200, c.request(get()).also { it.body.readAllBytes() }.status) }
            c.peerSettings.first { it != null }
            c.close()
        }

        /** A connection with the fixture's client settings, in 0-RTT when a ticket allows. */
        suspend fun connectEarly(): Http3Connection =
            client.connectEarly(server.localAddress, H3Fixtures.client(), settings = clientSettings)

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
         * Runs right after `connectEarly`, while the network drops the server's packets to the client (the client is in
         * 0-RTT; the server's PTO sends them again), with a function that stops the dropping; it stops when this returns at
         * the latest.
         */
        beforeRequest: (suspend (Http3Connection, () -> Unit) -> Unit)? = null,
        /** Sees the client's socket. */
        clientIo: (io.kuicksilver.http3.MemoryIo) -> Unit = {},
        /**
         * 1 while the network drops the server's packets to the resuming client (the client stays in 0-RTT); the test sets it
         * to 0, and the server's PTO then sends them again. Dropped, not queued: what the test holds back comes later, not in
         * the order it was sent.
         */
        clientHold: AtomicInt? = null,
        /** Sees the resuming client's HTTP/3 session before it starts. */
        clientSession: ((H3Session) -> Unit)? = null,
        /** false: the test ends the connection in [beforeRequest]; no request follows and the result is null. */
        sendRequest: Boolean = true,
        /** The resuming server's QUIC settings (its transport parameters). */
        resumerQuic: io.kuicksilver.quic.QuicConfig? = null,
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
            quicConfig: io.kuicksilver.quic.QuicConfig? = null,
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
                    this.server =
                        QuicServerConfig
                            .Builder(tls)
                            .apply {
                                earlyData = true
                                quicConfig?.let { quic = it }
                            }.build()
                    crypto = KslQuicCrypto
                    this.io = { io }
                }.build(),
            settings,
        )
        val first = server(b1, issuer)
        val second =
            try {
                Http3Endpoint.allowFewerUniStreamsForTest = resumerQuic != null
                server(b2, resumer, resumerQuic)
            } finally {
                Http3Endpoint.allowFewerUniStreamsForTest = false
            }
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
            // the hook is global: the first client session made from here on is this connection's, and only that one gets the
            // per-session hooks (a hook that waits for a rejection would spin on any other session)
            val taken = kotlin.concurrent.atomics.AtomicInt(0)
            if (clientSession != null) {
                H3Session.createdForTest = { if (!it.isServer && taken.compareAndSet(0, 1)) clientSession(it) }
            }
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
     * The critical streams of a 0-RTT connection are not held to a deadline when the peer's parameters (remembered, then
     * those of the handshake) allow the three unidirectional streams: a deadline there measured only this host's own
     * progress, and a loaded host closed connections to healthy servers. With a zero deadline, standing for a host that
     * cannot open and write them in any time, the early connection works whether the server accepts the 0-RTT, rejects it
     * (the streams are opened again under the new parameters), or the connection ends before the server's answer.
     */
    @Test fun negative_zeroRttIsNotHeldToTheCriticalStreamsDeadline(): Unit =
        runBlocking {
            H3Session.criticalStreamsDeadlineForTest = kotlin.time.Duration.ZERO
            try {
                withTimeout(30.seconds) {
                    assertEquals(
                        true,
                        earlyAcceptedAfterResuming(issuer = http3Settings {}, resumer = http3Settings {}, earlyRequest = true),
                    )
                    assertEquals(
                        false,
                        earlyAcceptedAfterResuming(
                            issuer = http3Settings {},
                            resumer = http3Settings { h3Datagram = false },
                            earlyRequest = true,
                        ),
                    )
                    val ended = kotlinx.coroutines.CompletableDeferred<Throwable?>()
                    val answer =
                        earlyAcceptedAfterResuming(
                            issuer = http3Settings {},
                            resumer = http3Settings {},
                            sendRequest = false,
                            beforeRequest = { c, _ ->
                                // the network drops the server's packets meanwhile: its answer has not arrived
                                assertFalse(c.quic.isHandshakeComplete, "the server's answer arrived")
                                c.close() // before the server's answer
                                ended.complete(withTimeout(10.seconds) { c.closed.await() })
                            },
                        )
                    assertNull(answer)
                    val end = withTimeout(10.seconds) { ended.await() }
                    assertFalse(
                        end is io.kuicksilver.http3.Http3Exception.Protocol &&
                            end.h3Code == io.kuicksilver.http3.Http3ErrorCode.GENERAL_PROTOCOL_ERROR,
                        "the connection ended for its critical streams: $end",
                    )
                }
            } finally {
                H3Session.criticalStreamsDeadlineForTest = null
            }
        }

    /**
     * RFC 9114 section 6.2 in 0-RTT: the remembered limits allowed the three unidirectional streams, so the attempt to open
     * the critical streams began without a deadline; the server then rejects the 0-RTT with transport parameters that allow
     * two (RFC 9000 section 7.4.1: the new ones apply), while that attempt is still opening its streams. From the answer on
     * the attempt is held to the deadline like one that began with such a limit, and the connection ends with
     * H3_GENERAL_PROTOCOL_ERROR; before, its third open waited until the connection ended.
     */
    @Test fun negative_rejectionWithFewerUniStreamsDuringTheAttemptGetsTheDeadline(): Unit =
        runBlocking {
            H3Session.criticalStreamsDeadlineForTest = 200.milliseconds
            try {
                // connectEarly returns once the SETTINGS went out, so here it throws the connection's error; before, it
                // waited until the connection ended
                val e =
                    assertFailsWith<io.kuicksilver.http3.Http3Exception.Protocol> {
                        withTimeout(10.seconds) {
                            earlyAcceptedAfterResuming(
                                issuer = http3Settings {},
                                resumer = http3Settings {},
                                resumerQuic = io.kuicksilver.quic.quicConfig { maxUniStreams = 2 },
                                clientHold = AtomicInt(0), // the server's answer is not held back
                                sendRequest = false,
                                clientSession = { session ->
                                    // the first attempt (generation 0, in 0-RTT) waits for the server's answer before it
                                    // opens anything
                                    session.criticalAttemptHookForTest = { step, gen ->
                                        if (step == H3Session.AttemptStep.Started && gen == 0) session.quic.awaitHandshake()
                                    }
                                },
                            )
                        }
                    }
                assertEquals(io.kuicksilver.http3.Http3ErrorCode.GENERAL_PROTOCOL_ERROR, e.h3Code)
            } finally {
                H3Session.criticalStreamsDeadlineForTest = null
            }
        }

    /**
     * The attempt chooses its deadline from two reads, whether the handshake is complete and how many unidirectional streams
     * may be opened. The server's answer (a rejection whose transport parameters allow two) lands between them here. With the
     * limit read first the attempt saw the remembered three and then a complete handshake, took no deadline and no watch,
     * and its third open waited until the connection ended; with the handshake state read first it sees the new limit and
     * gets the deadline.
     */
    @Test fun negative_answerBetweenTheDeadlineReadsStillGetsTheDeadline(): Unit =
        runBlocking {
            H3Session.criticalStreamsDeadlineForTest = 200.milliseconds
            try {
                val e =
                    assertFailsWith<io.kuicksilver.http3.Http3Exception.Protocol> {
                        withTimeout(10.seconds) {
                            earlyAcceptedAfterResuming(
                                issuer = http3Settings {},
                                resumer = http3Settings {},
                                resumerQuic = io.kuicksilver.quic.quicConfig { maxUniStreams = 2 },
                                clientHold = AtomicInt(0),
                                sendRequest = false,
                                clientSession = { session ->
                                    session.criticalReadsHookForTest = { gen -> if (gen == 0) session.quic.awaitHandshake() }
                                },
                            )
                        }
                    }
                assertEquals(io.kuicksilver.http3.Http3ErrorCode.GENERAL_PROTOCOL_ERROR, e.h3Code)
            } finally {
                H3Session.criticalStreamsDeadlineForTest = null
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
                // the server's packets are dropped, so the client stays in 0-RTT, until its first attempt opened its streams
                val hold = AtomicInt(1)
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
                    ) { c, resumed ->
                        val s = resumed().single()
                        s.session.goAwayReceived.first { it != null }
                        assertEquals(8L, s.session.goAwayReceived.value, "the GOAWAY went again on the new control stream")
                        // a marker sent after the replay: the control stream is in order, so a PRIORITY_UPDATE replayed by mistake
                        // has been read once the marker is (review 2026-10-28 quic-h3.md R5)
                        c.session.sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(4))
                        s.session.goAwayReceived.first { it == 4L }
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

    /**
     * RFC 9114 section 7.2.4.2: "Clients SHOULD store the settings the server provided in the HTTP/3 connection where
     * resumption information was provided", and "MUST comply with stored settings ... when attempting 0-RTT". The ticket
     * keeps the server's SETTINGS; a 0-RTT request above the stored SETTINGS_MAX_FIELD_SECTION_SIZE fails locally before
     * the server's SETTINGS of the new connection arrived, and one within it is answered.
     */
    @Test fun storedSettingsBindTheZeroRttRequests(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()) { maxFieldSectionSize = 1_000 }.use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
                    assertEquals(1_000L, c.session.storedPeerSettings?.get(maxField))
                    val big =
                        http3Request("GET", "server.test", "/") {
                            headers = Http3Headers.of("x-big" to "v".repeat(2_000))
                            @OptIn(ExperimentalKuicksilverApi::class)
                            allowEarlyData = true
                        }
                    kotlin.test.assertFailsWith<io.kuicksilver.http3.Http3Exception.FieldSectionTooLarge> { c.request(big) }
                    assertTrue(c.peerSettings.value == null, "decided before the server's SETTINGS of this connection")
                    assertEquals(
                        "GET ok",
                        c
                            .request(f.get(early = true))
                            .body
                            .readAllBytes()
                            .decodeToString(),
                    )
                    c.quic.awaitHandshake()
                    assertEquals(true, c.quic.earlyDataAccepted)
                }
            }
        }

    /**
     * RFC 9114 section 7.2.4.2: a server that accepted 0-RTT and then sends SETTINGS that lower a stored value, or omit one
     * stored with a non-default value, ends the connection with H3_SETTINGS_ERROR. The server here sends other SETTINGS
     * than its ticket context says (a test hook); ours never does.
     */
    @Test fun negative_settingsIncompatibleWithTheStoredOnesAreSettingsError(): Unit =
        runBlocking {
            val changes =
                listOf<(List<Pair<Long, Long>>) -> List<Pair<Long, Long>>>(
                    { l -> l.map { if (it.first == maxField) it.first to 500L else it } },
                    { l -> l.filter { it.first != maxField } },
                )
            for (change in changes) {
                Fixture(Http3EarlyDataPolicy.WaitForHandshake()) { maxFieldSectionSize = 1_000 }.use { f ->
                    withTimeout(20.seconds) {
                        f.start()
                        f.warmUp()
                    }
                    H3Session.createdForTest = { if (it.isServer) it.ourSettingsForTest = change }
                    try {
                        // the server's SETTINGS can arrive (in 0.5-RTT) while connectEarly is still starting the session,
                        // which then fails with the connection error itself; otherwise the connection ends with it. Any other
                        // end (a rejected 0-RTT, a transport failure on a loaded host) fails here with what it was
                        val end: Throwable =
                            withTimeout(20.seconds) {
                                try {
                                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                                    // a rejected 0-RTT would leave the connection healthy and closed never complete:
                                    // say so at once (a handshake that fails instead ends the connection, seen below)
                                    if (runCatching { c.quic.awaitHandshake() }.isSuccess) {
                                        assertEquals(true, c.quic.earlyDataAccepted, "the server did not accept 0-RTT")
                                    }
                                    c.closed.await()
                                } catch (e: io.kuicksilver.http3.Http3Exception) {
                                    e
                                } catch (e: io.kuicksilver.quic.QuicException) {
                                    e
                                }
                            }
                        val e = kotlin.test.assertIs<io.kuicksilver.http3.Http3Exception.Protocol>(end, "${end::class.simpleName}: $end")
                        assertEquals(io.kuicksilver.http3.Http3ErrorCode.SETTINGS_ERROR, e.h3Code, "$e")
                        // raised by the check of the SETTINGS stored for 0-RTT, which applies only once 0-RTT was accepted
                        assertTrue("0-RTT" in e.message.orEmpty(), "$e")
                    } finally {
                        H3Session.createdForTest = null
                    }
                }
            }
        }

    private val maxField = io.kuicksilver.http3.frame.SettingsId.MAX_FIELD_SECTION_SIZE

    /**
     * draft-ietf-webtrans-http3-16 section 3.2: "A client MUST close the connection with H3_SETTINGS_ERROR if the SETTINGS
     * frame received in the resumed connection reduces any flow control values from the cached previous values": a
     * server that accepted 0-RTT and then sends a lower SETTINGS_WT_INITIAL_MAX_DATA, or omits it.
     */
    @Test fun negative_webTransportFlowControlLoweredAfter0RttIsSettingsError(): Unit =
        runBlocking {
            val data = io.kuicksilver.http3.frame.SettingsId.WT_INITIAL_MAX_DATA
            val changes =
                listOf<(List<Pair<Long, Long>>) -> List<Pair<Long, Long>>>(
                    { l -> l.map { if (it.first == data) it.first to it.second - 1 else it } },
                    { l -> l.filter { it.first != data } },
                )
            for (change in changes) {
                Fixture(Http3EarlyDataPolicy.WaitForHandshake()) {
                    enableConnectProtocol = true
                    webTransport = true
                }.use { f ->
                    withTimeout(20.seconds) {
                        f.start()
                        f.warmUp()
                    }
                    H3Session.createdForTest = { if (it.isServer) it.ourSettingsForTest = change }
                    try {
                        val end: Throwable =
                            withTimeout(20.seconds) {
                                try {
                                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                                    if (runCatching { c.quic.awaitHandshake() }.isSuccess) {
                                        assertEquals(true, c.quic.earlyDataAccepted, "the server did not accept 0-RTT")
                                    }
                                    c.closed.await()
                                } catch (e: io.kuicksilver.http3.Http3Exception) {
                                    e
                                } catch (e: io.kuicksilver.quic.QuicException) {
                                    e
                                }
                            }
                        val e = kotlin.test.assertIs<io.kuicksilver.http3.Http3Exception.Protocol>(end, "${end::class.simpleName}: $end")
                        assertEquals(io.kuicksilver.http3.Http3ErrorCode.SETTINGS_ERROR, e.h3Code, "$e")
                    } finally {
                        H3Session.createdForTest = null
                    }
                }
            }
        }

    /**
     * Section 3.2: "If the server accepts 0-RTT, the server MUST NOT reduce these initial flow control values": a server
     * whose WebTransport flow-control values or session limit changed accepts no early data from a ticket issued before;
     * one with the same values does.
     */
    @Test fun webTransportFlowControlChangeInvalidatesEarlyData(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val issuer = io.kuicksilver.http3.webtransport.wtOn
                val changed =
                    listOf<Http3Settings.Builder.() -> Unit>(
                        { webTransportInitialMaxData = 1000 },
                        { webTransportInitialMaxStreamsBidi = 3 },
                        { webTransportInitialMaxStreamsUni = 3 },
                        { webTransportMaxSessions = 2 },
                    )
                for (change in changed) {
                    assertEquals(false, earlyAcceptedAfterResuming(issuer = issuer, resumer = issuer.toBuilder().apply(change).build()))
                }
                assertEquals(true, earlyAcceptedAfterResuming(issuer = issuer, resumer = issuer))
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

    /**
     * draft-ietf-webtrans-http3-16 section 3.2: "Clients cannot initiate WebTransport sessions in 0-RTT packets, as the
     * CONNECT method is not considered safe". A client that does anyway: [early] sends a WebTransport CONNECT on [c]'s
     * QUIC connection while its 0-RTT is still unconfirmed, and returns its stream.
     */
    private suspend fun earlyWebTransportConnect(c: Http3Connection): io.kuicksilver.quic.QuicStream {
        assertTrue(!c.quic.isHandshakeComplete, "connectEarly returned before the handshake")
        val st = c.quic.openBidi()
        st.output.writeFully(
            RawPeer(c.quic).headers(
                st.id,
                listOf(
                    ":method" to "CONNECT",
                    ":protocol" to "webtransport-h3",
                    ":scheme" to "https",
                    ":authority" to "server.test",
                    ":path" to "/wt",
                ),
            ),
        )
        st.output.flush()
        return st
    }

    private val wtServer: Http3Settings.Builder.() -> Unit = {
        enableConnectProtocol = true
        webTransport = true
        webTransportMaxSessions = 1
    }
    private val wtClient =
        io.kuicksilver.http3.http3Settings {
            enableConnectProtocol = true
            webTransport = true
        }

    /** The server's WebTransport sessions are all gone and nothing waits in its fair queues. */
    private suspend fun assertNoWebTransportLeft(s: H3Session) {
        val left =
            withTimeoutOrNull(5.seconds) {
                while (withContext(s.dispatcher) { s.wtSessions.isNotEmpty() || !s.wtFairness.idleForTest }) kotlinx.coroutines.yield()
            }
        assertTrue(left != null, "a WebTransport session slot or a fair queue turn is left")
    }

    /** A WebTransport CONNECT that came in 0-RTT is held until the handshake completes, then admitted as usual. */
    @Test fun negative_webTransportConnectIn0RttWaitsForTheHandshake(): Unit =
        runBlocking {
            val ranAfterHandshake = kotlinx.coroutines.CompletableDeferred<Boolean>()
            val onConnect: suspend (io.kuicksilver.http3.Http3ServerRequest, Http3Connection) -> Unit = { r, c ->
                ranAfterHandshake.complete(c.quic.isHandshakeComplete)
                r.acceptWebTransport()
            }
            Fixture(Http3EarlyDataPolicy.WaitForHandshake(), wtClient, onConnect, wtServer).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.connectEarly()
                    val st = earlyWebTransportConnect(c)
                    assertEquals(
                        "200",
                        io.kuicksilver.http3.webtransport
                            .readHeaders(st)[":status"],
                    )
                    assertEquals(true, c.quic.earlyDataAccepted, "the CONNECT went in accepted 0-RTT")
                    assertEquals(1, f.heldEarly, "the gate held it")
                    assertTrue(ranAfterHandshake.await(), "the application saw it only after the handshake")
                    st.reset(0x10c) // H3_REQUEST_CANCELLED
                    st.stopSending(0x10c)
                    assertNoWebTransportLeft(f.accepted.last().session)
                    c.close()
                }
            }
        }

    /**
     * Under Reject425 a WebTransport CONNECT in 0-RTT is answered 425 Too Early: it never reached the application, and its
     * slot is free again (with webTransportMaxSessions = 1 the client's CONNECT after the handshake is admitted).
     */
    @Test fun negative_webTransportConnectAnswered425LeavesNoSlot(): Unit =
        runBlocking {
            val seen = AtomicInt(0)
            val onConnect: suspend (io.kuicksilver.http3.Http3ServerRequest, Http3Connection) -> Unit = { r, _ ->
                seen.incrementAndFetch()
                r.acceptWebTransport()
            }
            Fixture(Http3EarlyDataPolicy.Reject425(), wtClient, onConnect, wtServer).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.connectEarly()
                    val st = earlyWebTransportConnect(c)
                    assertEquals(
                        "425",
                        io.kuicksilver.http3.webtransport
                            .readHeaders(st)[":status"],
                    )
                    assertEquals(0, seen.load(), "the application never saw it")
                    val s = f.accepted.last().session
                    assertNoWebTransportLeft(s)
                    c.quic.awaitHandshake()
                    val session = c.webTransport(http3Request("CONNECT", "server.test", "/wt"))
                    assertEquals(1, seen.load())
                    assertTrue(!session.closed.isCompleted)
                    c.close()
                }
            }
        }

    /**
     * A WebTransport CONNECT held for a handshake that never completes (the connection is lost first) is dropped: the
     * application never sees it, and nothing of it stays.
     */
    @Test fun negative_webTransportConnectHeldWhenTheConnectionIsLostIsDropped(): Unit =
        runBlocking {
            val seen = AtomicInt(0)
            val onConnect: suspend (io.kuicksilver.http3.Http3ServerRequest, Http3Connection) -> Unit = { r, _ ->
                seen.incrementAndFetch()
                r.acceptWebTransport()
            }
            Fixture(Http3EarlyDataPolicy.WaitForHandshake(), wtClient, onConnect, wtServer).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    f.net.delay = 50.milliseconds
                    val c = f.connectEarly()
                    earlyWebTransportConnect(c)
                    while (f.heldEarly < 1) kotlinx.coroutines.yield()
                    // the client's handshake never reaches the server, which then loses the connection
                    f.net.drop = { from, _, _ -> from.port == 1111 }
                    val server = f.accepted.last()
                    assertTrue(!server.quic.isHandshakeComplete)
                    server.quic.close()
                    assertNoWebTransportLeft(server.session)
                    assertEquals(0, seen.load(), "the held CONNECT never reached the application")
                    c.close()
                }
            }
        }

    /**
     * A WebTransport CONNECT in 0-RTT the server rejects (its flow-control settings changed since the ticket, section
     * 3.2): the transport drops it, so the server never sees it and keeps nothing of it, and the stream fails on the
     * client.
     */
    @Test fun negative_webTransportConnectInRejected0RttLeavesNothing(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                val seen = AtomicInt(0)
                var st: io.kuicksilver.quic.QuicStream? = null
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer =
                            io.kuicksilver.http3.http3Settings {
                                enableConnectProtocol = true
                                webTransport = true
                            },
                        resumer =
                            io.kuicksilver.http3.http3Settings {
                                enableConnectProtocol = true
                                webTransport = true
                                webTransportInitialMaxData = 2_000_000
                            },
                        resumerRequests = seen,
                        clientSettings = wtClient,
                        beforeRequest = { c, release ->
                            st = earlyWebTransportConnect(c)
                            release()
                        },
                        after = { _, resumed ->
                            assertTrue(
                                runCatching {
                                    io.kuicksilver.http3.webtransport
                                        .readHeaders(st!!)
                                }.isFailure,
                            )
                            for (s in resumed()) assertNoWebTransportLeft(s.session)
                        },
                    )
                assertEquals(false, accepted, "the server rejected the 0-RTT")
                assertEquals(1, seen.load(), "only the request sent after the handshake reached the server")
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
                    // the rejected request is forgotten too, not only the one that ran (its stream, PRIORITY_UPDATE routing)
                    val s = f.accepted.last().session
                    val left =
                        withTimeoutOrNull(5.seconds) {
                            while (withContext(s.dispatcher) { s.activeServerRequests.isNotEmpty() }) kotlinx.coroutines.yield()
                        }
                    assertTrue(left != null, "a request the server answered with 425 is still registered")
                }
            }
        }

    /**
     * The server holds a request stream's MAX_STREAMS credit until its handler is done (Rapid Reset, RFC 9114 section
     * 10.5): for a request that came in accepted 0-RTT nothing stays held once it was answered.
     */
    @Test fun earlyRequestHoldsNoStreamCreditOnceAnsweredWhenAccepted(): Unit = noCreditHeldAfterTheEarlyRequest(accept = true)

    /** The same after a rejected 0-RTT: the request the client sends again holds nothing once answered, and the dropped one never did. */
    @Test fun earlyRequestHoldsNoStreamCreditOnceAnsweredWhenRejected(): Unit = noCreditHeldAfterTheEarlyRequest(accept = false)

    private fun noCreditHeldAfterTheEarlyRequest(accept: Boolean) =
        runBlocking {
            withTimeout(30.seconds) {
                val accepted =
                    earlyAcceptedAfterResuming(
                        issuer = http3Settings {},
                        resumer = if (accept) http3Settings {} else http3Settings { h3Datagram = false },
                        earlyRequest = true,
                        after = { _, servers ->
                            for (sc in servers()) {
                                awaitCondition("the server's held stream credit going back") {
                                    QuicStreamLimits.heldPeerBidiStreamsForTest(sc.quic) == 0
                                }
                            }
                        },
                    )
                assertEquals(accept, accepted)
            }
        }

    /**
     * The connection is lost while the server runs an early request and before the client has the server's handshake
     * answer: the server's request ends (its answer fails), and nothing of it stays registered.
     */
    @Test fun earlyRequestEndsWhenTheConnectionIsLostBeforeTheAnswer(): Unit =
        runBlocking {
            Fixture(Http3EarlyDataPolicy.WaitForHandshake()).use { f ->
                withTimeout(20.seconds) {
                    f.start()
                    f.warmUp()
                    val warmed = f.accepted.size
                    f.last = null
                    f.net.drop = { from, _, _ -> from == f.server.localAddress } // the client never hears from the server
                    val c = f.client.connectEarly(f.server.localAddress, H3Fixtures.client())
                    val request = f.scope.launch { runCatching { c.request(f.get(early = true)) } }
                    awaitCondition("the server taking the early request") { f.accepted.size > warmed && f.last != null }
                    c.close()
                    request.cancel()
                    val sc = f.accepted.last()
                    withTimeout(10.seconds) { sc.closed.await() }
                    awaitCondition("the early request ending on the server") {
                        withContext(sc.session.dispatcher) { sc.session.activeServerRequests.isEmpty() }
                    }
                }
            }
        }
}
