// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(DelicateKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.discard
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Two crossed in-memory channels: what the client writes, the server reads, and the other way round. */
internal open class ChannelPair {
    private val c2s = ByteChannel(autoFlush = true)
    private val s2c = ByteChannel(autoFlush = true)
    open val clientIn: ByteReadChannel get() = s2c
    open val clientOut: ByteWriteChannel get() = c2s
    open val serverIn: ByteReadChannel get() = c2s
    open val serverOut: ByteWriteChannel get() = s2c

    /** Simulates a transport that ends without close_notify in the client's receive direction. */
    fun killServerToClient() {
        s2c.close()
    }
}

/** [ChannelPair] over [BoundedPipe]s: each direction holds a few KiB, so a side that stops reading stops its peer's writes. */
internal class BoundedChannelPair : ChannelPair() {
    private val c2s = BoundedPipe()
    private val s2c = BoundedPipe()
    override val clientIn: ByteReadChannel get() = s2c.read
    override val clientOut: ByteWriteChannel get() = c2s.write
    override val serverIn: ByteReadChannel get() = c2s.read
    override val serverOut: ByteWriteChannel get() = s2c.write
}

internal suspend fun ByteReadChannel.readExactly(n: Int): ByteArray {
    val out = ByteArray(n)
    var off = 0
    while (off <
        n
    ) {
        val r = readAvailable(out, off, n - off)
        if (r <
            0
        ) {
            throw closedCause ?: IllegalStateException("EOF after $off of $n")
        }
        off += r
    }
    return out
}

private val testScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

/** Starts both handshakes concurrently; failures stay inside the Deferreds so tests can assert on them. */
internal fun connect(
    client: TlsConfig,
    server: TlsConfig,
    pair: ChannelPair = ChannelPair(),
    clientCache: SessionCache = SessionCache.Default,
): Pair<Deferred<TlsConnection>, Deferred<TlsConnection>> {
    val c = testScope.async { TlsConnection.client(pair.clientIn, pair.clientOut, client, EmptyCoroutineContext, clientCache) }
    val s = testScope.async { TlsConnection.server(pair.serverIn, pair.serverOut, server) }
    return c to s
}

internal object TcpFixtures {
    fun client(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
        tlsConfig(TlsRole.Client) {
            alpn = listOf("x1")
            serverName =
                "server.test"
            trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            block()
        }

    fun server(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("x1")
            identity =
                TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            block()
        }
}

class TlsConnectionTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private fun both(
        client: TlsConfig = TcpFixtures.client(),
        server: TlsConfig = TcpFixtures.server(),
        pair: ChannelPair = ChannelPair(),
    ): Pair<TlsConnection, TlsConnection> =
        runBlocking {
            val pair2 = connect(client, server, pair)
            withTimeout(20.seconds) { pair2.first.await() to pair2.second.await() }
        }

    @Test fun echoOneMegabyteTls13(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                assertEquals("x1", c.negotiatedAlpn)
                assertEquals(TlsVersion.Tls13, c.protocolVersion)
                assertEquals(1, c.peerCertificates.size)
                val data = ByteArray(1 shl 20) { (it * 7).toByte() }
                val echo =
                    async {
                        val got = s.input.readExactly(data.size)
                        s.output.writeFully(got, 0, got.size)
                        s.output.flush()
                    }
                c.output.writeFully(data, 0, data.size)
                c.output.flush()
                val back = withTimeout(30.seconds) { c.input.readExactly(data.size) }
                echo.await()
                assertContentEquals(data, back)
                assertContentEquals(c.exportKeyingMaterial("l", null, 16), s.exportKeyingMaterial("l", null, 16))
                assertContentEquals(c.channelBinding(), s.channelBinding())
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun fullDuplexKeepsRecordOrder(): Unit =
        runBlocking(Dispatchers.Default) {
            // both pumps drain ciphertext to the transport: the reader after each read, the writer after each write. Two drains
            // racing reordered records on the wire (the peer answered bad_record_mac; found by the soak)
            repeat(4) { round ->
                val (c, s) = both()
                try {
                    val size = 4 shl 20
                    val up = ByteArray(size) { (it * 7 + round).toByte() }
                    val down = ByteArray(size) { (it * 13 + round).toByte() }
                    withTimeout(60.seconds) {
                        val sw =
                            async {
                                s.output.writeFully(down, 0, size)
                                s.output.flush()
                            }
                        val cw =
                            async {
                                c.output.writeFully(up, 0, size)
                                c.output.flush()
                            }
                        val sr = async { s.input.readExactly(size) }
                        val cr = async { c.input.readExactly(size) }
                        assertContentEquals(up, sr.await(), "client to server, round $round")
                        assertContentEquals(down, cr.await(), "server to client, round $round")
                        sw.await()
                        cw.await()
                    }
                } finally {
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun fullDuplexOverFullTransportsNeverStalls(): Unit =
        runBlocking(Dispatchers.Default) {
            // both applications write and read at once over transports that hold a few KiB: a reader pump that writes the
            // writer's ciphertext and waits for room on its full transport stops reading, and when both peers' reader pumps
            // do, neither transport empties again
            repeat(4) { round ->
                val (c, s) = both(pair = BoundedChannelPair())
                try {
                    val size = 2 shl 20
                    val up = ByteArray(size) { (it * 7 + round).toByte() }
                    val down = ByteArray(size) { (it * 13 + round).toByte() }
                    val done =
                        withTimeoutOrNull(30.seconds) {
                            val sw = async { s.output.writeFully(down, 0, size).also { s.output.flush() } }
                            val cw = async { c.output.writeFully(up, 0, size).also { c.output.flush() } }
                            val sr = async { s.input.readExactly(size) }
                            val cr = async { c.input.readExactly(size) }
                            assertContentEquals(up, sr.await(), "client to server, round $round")
                            assertContentEquals(down, cr.await(), "server to client, round $round")
                            sw.await()
                            cw.await()
                        }
                    assertTrue(done != null, "full-duplex transfer over full transports stalled, round $round")
                } finally {
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun shutdownDeliversEofToPeer(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                c.output.writeFully("bye".encodeToByteArray(), 0, 3)
                c.shutdown()
                assertContentEquals("bye".encodeToByteArray(), s.input.readExactly(3))
                val tail = ByteArray(8)
                assertEquals(-1, withTimeout(5.seconds) { s.input.readAvailable(tail, 0, 8) }, "clean EOF after close_notify")
                assertNull(s.input.closedCause)
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun negative_truncatedTlsStreamIsError(): Unit =
        runBlocking {
            val pair = ChannelPair()
            val (c, s) = both(pair = pair)
            try {
                pair.killServerToClient()
                val e =
                    assertFailsWith<Exception> {
                        withTimeout(5.seconds) { c.input.readExactly(1) }
                    } // ktor wraps the close cause in ClosedByteChannelException
                val tls = generateSequence<Throwable>(e) { it.cause }.filterIsInstance<TlsException>().firstOrNull()
                assertTrue(
                    (tls is TlsException.Protocol && tls.message!!.contains("truncation")) || e.message!!.contains("truncation"),
                    "got $e / cause ${e.cause}",
                )
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun keyUpdateBothDirections(): Unit =
        runBlocking {
            val (c, s) = both()
            try {
                c.keyUpdate(requestPeer = true)
                roundTrip(c, s, 3000)
                s.keyUpdate()
                roundTrip(c, s, 3000)
            } finally {
                c.close()
                s.close()
            }
        }

    private suspend fun roundTrip(
        c: TlsConnection,
        s: TlsConnection,
        n: Int,
    ) {
        val data = ByteArray(n) { it.toByte() }
        c.output.writeFully(data, 0, n)
        c.output.flush()
        val got = withTimeout(5.seconds) { s.input.readExactly(n) }
        assertContentEquals(data, got)
        s.output.writeFully(got, 0, n)
        s.output.flush()
        assertContentEquals(data, withTimeout(5.seconds) { c.input.readExactly(n) })
    }

    @Test fun negative_alpnMismatchClosesConnection() {
        val pair = ChannelPair()
        val (cd, sd) = connect(TcpFixtures.client { alpn = listOf("other") }, TcpFixtures.server(), pair)
        runBlocking {
            val e = assertFailsWith<TlsException.AlertReceived> { withTimeout(10.seconds) { cd.await() } }
            assertEquals(120, e.code)
            assertFailsWith<TlsException> { withTimeout(10.seconds) { sd.await() } }
        }
    }

    @Test fun negative_tls12WithoutEmsRejected() {
        // our side never disables EMS; a TLS 1.2 handshake with EMS succeeds and reports Tls12
        val (c, s) =
            both(
                TcpFixtures.client {
                    versions = TlsVersions.Tls12And13
                    cipherSuites =
                        CipherSuites(listOf("TLS_AES_128_GCM_SHA256"))
                },
                TcpFixtures.server { versions = TlsVersions.Tls12And13 },
            )
        runBlocking {
            try {
                assertEquals(TlsVersion.Tls13, c.protocolVersion)
            } finally {
                c.close()
                s.close()
            }
        }
    }

    @Test fun handshakeTimeout() {
        val pair = ChannelPair()
        val e =
            runBlocking {
                assertFailsWith<TlsException.Protocol> {
                    withTimeout(10.seconds) {
                        TlsConnection.client(
                            pair.clientIn,
                            pair.clientOut,
                            TcpFixtures.client {
                                handshakeTimeout =
                                    1.seconds
                            },
                        )
                    }
                }
            }
        assertTrue(e.message!!.contains("timed out"), e.message)
    }

    @Test fun cancellationNotWrapped() {
        val pair = ChannelPair()
        runBlocking {
            assertFailsWith<TimeoutCancellationException> {
                withTimeout(1.seconds) {
                    TlsConnection.client(
                        pair.clientIn,
                        pair.clientOut,
                        TcpFixtures.client {
                            handshakeTimeout =
                                30.seconds
                        },
                    )
                }
            }
        }
    }
}

class TlsServerTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private val proxyIdentity get() = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())
    private val serverIdentity get() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    @Test fun sniSelectorOverridesIdentity(): Unit =
        runBlocking {
            val seen = CompletableDeferred<ClientHelloInfo>()
            val server =
                TcpFixtures.server {
                    identity = proxyIdentity
                    sniSelector =
                        { info ->
                            seen.complete(info)
                            if (info.serverName == "server.test") ServerTlsOverride(serverIdentity) else null
                        }
                }
            val (cd, sd) = connect(TcpFixtures.client(), server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals("server.test", seen.await().serverName)
                assertEquals(listOf("x1"), seen.await().alpn)
                assertTrue(seen.await().signatureSchemes.isNotEmpty())
                assertEquals(Certificate(TestCerts.server), c.peerCertificates[0])
            } finally {
                c.close()
                s.close()
            }
        }

    @Test fun negative_unrecognizedSniFatal() {
        val server =
            TcpFixtures.server {
                identity = proxyIdentity
                sniSelector = { null }
            }
        val (cd, _) = connect(TcpFixtures.client(), server)
        runBlocking {
            val e = assertFailsWith<TlsException.AlertReceived> { withTimeout(10.seconds) { cd.await() } }
            assertEquals(112, e.code)
        }
    }

    @Test fun noSniUsesDefaultIdentity(): Unit =
        runBlocking {
            val seen = CompletableDeferred<String?>()
            val server =
                TcpFixtures.server {
                    sniSelector = { info ->
                        seen.complete(info.serverName)
                        null
                    }
                }
            val client =
                tlsConfig(TlsRole.Client) {
                    alpn = listOf("x1")
                    serverName = "127.0.0.1"
                    trust =
                        TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
                } // IP literal: no SNI
            val (cd, sd) = connect(client, server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertNull(seen.await(), "no SNI for an IP literal")
                assertEquals(1, c.peerCertificates.size)
            } finally {
                c.close()
                s.close()
            }
        }

    /** RFC 6066 section 3 ( literal IP addresses are not permitted in server_name): an IP serverName is never sent as SNI, also when ExpectedName supplies a DNS reference. */
    @Test fun ipServerNameNeverSentAsSni(): Unit =
        runBlocking {
            val seen = CompletableDeferred<String?>()
            val server =
                TcpFixtures.server {
                    sniSelector = { info ->
                        seen.complete(info.serverName)
                        null
                    }
                }
            val client =
                tlsConfig(TlsRole.Client) {
                    alpn = listOf("x1")
                    serverName = "127.0.0.1"
                    trust =
                        TrustConfig.ExpectedName("server.test", base = TrustConfig.AnchoredCa(listOf(Fixtures.testCa)))
                }
            val (cd, sd) = connect(client, server)
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertNull(withTimeout(5.seconds) { seen.await() }, "no SNI for an IP literal")
            } finally {
                c.close()
                s.close()
            }
        }

    /** ClientAuth.Optional + Pinned (review T3): a client without a certificate is accepted (TlsConfig.clientAuth KDoc), a presented one must match a pin. */
    @Test fun clientAuthOptionalPinnedAcceptsClientWithoutCertificate(): Unit =
        runBlocking {
            val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            val server =
                TcpFixtures.server {
                    clientAuth = ClientAuth.Optional
                    trust = TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = ca)
                }
            val (c, s) = both(TcpFixtures.client(), server)
            try {
                assertTrue(s.peerCertificates.isEmpty(), "no client certificate")
            } finally {
                c.close()
                s.close()
            }
            val (_, sd) = connect(TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }, server)
            assertIs<VerifyReason.PinMismatch>(assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { sd.await() } }.reason)
        }

    @Test fun clientAuthRequiredAnchoredCaAndPinned(): Unit =
        runBlocking {
            val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            val ok =
                both(
                    TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) },
                    TcpFixtures.server {
                        clientAuth =
                            ClientAuth.Required
                        ; trust = ca
                    },
                )
            try {
                assertEquals(Certificate(TestCerts.client), ok.second.peerCertificates[0])
            } finally {
                ok.first.close()
                ok.second.close()
            }
            val (_, bad) =
                connect(
                    TcpFixtures.client {
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.clientOtherCa), TestCerts.clientOtherCaKey.copyOf())
                    },
                    TcpFixtures.server {
                        clientAuth =
                            ClientAuth.Required
                        ; trust = ca
                    },
                )
            assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { bad.await() } }
            val pinned = TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = ca)
            val (_, pinBad) =
                connect(
                    TcpFixtures.client {
                        identity =
                            TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                    },
                    TcpFixtures.server {
                        clientAuth =
                            ClientAuth.Required
                        ; trust = pinned
                    },
                )
            val e = assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { pinBad.await() } }
            assertIs<VerifyReason.PinMismatch>(e.reason)
        }

    /**
     * Threat model 5, item 2: a server pinning client certificates issues no ticket before its pin verdict. TLS 1.3: the
     * ticket is explicit, after the verdict, so a rejected client caches nothing. TLS 1.2 (a raw ksl client, TlsConfig cannot cap a peer
     * at 1.2): the in-handshake ticket is suppressed, so the client holds no resumable session although its handshake completed.
     */
    @Test fun negative_serverTicketBeforePinVerdict(): Unit =
        runBlocking {
            val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            // the client's certificate does not match
            val pinned = TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = ca)
            val server =
                TcpFixtures.server {
                    versions = TlsVersions.Tls12And13
                    clientAuth = ClientAuth.Required
                    trust = pinned
                }
            val (cd, sd) =
                connect(
                    TcpFixtures.client {
                        identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                    },
                    server,
                )
            assertIs<VerifyReason.PinMismatch>(assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { sd.await() } }.reason)
            runCatching { withTimeout(10.seconds) { cd.await() }.close() }
            delay(200)
            assertEquals(0, SessionCache.Default.size(), "TLS 1.3: no ticket reached the rejected client")

            val pair = ChannelPair()
            val sd2 = testScope.async { TlsConnection.server(pair.serverIn, pair.serverOut, server) }
            val ctx = Ksl.ctxNew(KslConst.CLIENT)
            try {
                Ksl.ctxSetAlpn(ctx, byteArrayOf(2, 'x'.code.toByte(), '1'.code.toByte()))
                Ksl.ctxSetIdentity(ctx, listOf(TestCerts.client), TestCerts.clientKey.copyOf())
                Ksl.ctxSetOption(ctx, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
                Ksl.ctxSetOption(ctx, KslConst.OPT_MAX_VERSION, KslConst.TLS1_2)
                Ksl.ctxSetOption(ctx, KslConst.OPT_VERIFY_MODE, KslConst.VERIFY_NONE)
                Ksl.ctxFreeze(ctx)
                val ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
                try {
                    assertEquals(
                        KslConst.OK,
                        withTimeout(10.seconds) {
                            rawHandshake(ssl, pair.clientIn, pair.clientOut)
                        },
                        "the TLS 1.2 client finishes before the server's verdict",
                    )
                    assertEquals(byteArrayOf(0x03, 0x03).toList(), Ksl.sslGet(ssl, KslConst.GET_VERSION).toList())
                    assertIs<VerifyReason.PinMismatch>(
                        assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { sd2.await() } }.reason,
                    )
                    assertEquals(0L, Ksl.sslGet1Session(ssl), "TLS 1.2: no resumable session was handed out before the verdict")
                } finally {
                    Ksl.sslFree(ssl)
                }
            } finally {
                Ksl.ctxFree(ctx)
            }
        }

    /**
     * Threat model 5, item 2, through an SNI override (review T1): the base configuration asks for no client certificate and
     * issues tickets in the handshake, the selector's override pins client certificates. The override's settings must be in
     * effect: no ticket before its pin verdict, so a client whose CA-issued certificate is not pinned can never resume past the pin.
     */
    @Test fun negative_sniOverridePinnedClientsNoTicketBeforeVerdict(): Unit =
        runBlocking {
            val pinned =
                TrustConfig.Pinned(setOf(Certificate(TestCerts.proxy).spkiSha256), base = TrustConfig.AnchoredCa(listOf(Fixtures.testCa)))
            val server =
                TcpFixtures.server {
                    sniSelector = { ServerTlsOverride(serverIdentity, clientAuth = ClientAuth.Required, trust = pinned) }
                }
            val client = TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }
            repeat(2) { attempt ->
                val (cd, sd) = connect(client, server)
                val e = assertFailsWith<TlsException.Verify>("attempt $attempt") { withTimeout(10.seconds) { sd.await() } }
                assertIs<VerifyReason.PinMismatch>(e.reason, "attempt $attempt: the pin is checked")
                // the server's close_notify follows anything it sent: reading to the end has processed a ticket, if one came
                runCatching {
                    withTimeout(10.seconds) {
                        val c = cd.await()
                        try {
                            c.input.discard()
                        } finally {
                            c.close()
                        }
                    }
                }
                assertEquals(0, SessionCache.Default.size(), "attempt $attempt: no ticket reached the rejected client")
            }
        }

    /** Drives a raw `ksl` TCP session over channels until its handshake completes; returns the last drive result. */
    private suspend fun rawHandshake(
        ssl: Long,
        input: ByteReadChannel,
        output: ByteWriteChannel,
    ): Int {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val rc = Ksl.drive(ssl)
            while (true) {
                val n = Ksl.tcpDrain(ssl, buf, 0, buf.size)
                if (n <= 0) break
                output.writeFully(buf, 0, n)
            }
            output.flush()
            if (rc != KslConst.WANT_READ) return rc
            val n = input.readAvailable(buf, 0, buf.size)
            if (n < 0) return rc
            var off = 0
            while (off < n) {
                val used = Ksl.tcpFeed(ssl, buf, off, n - off)
                if (used <= 0) return rc
                off += used
            }
        }
    }

    private fun both(
        client: TlsConfig,
        server: TlsConfig,
    ): Pair<TlsConnection, TlsConnection> =
        runBlocking {
            val (cd, sd) = connect(client, server)
            withTimeout(20.seconds) {
                cd.await() to
                    sd.await()
            }
        }
}

class SessionResumptionTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private fun once(
        client: TlsConfig,
        server: TlsConfig,
        exchange: Boolean = true,
    ): Pair<TlsConnection, Boolean> =
        runBlocking {
            val (cd, sd) = connect(client, server)
            val c = withTimeout(20.seconds) { cd.await() }
            val s = withTimeout(20.seconds) { sd.await() }
            if (exchange) {
                c.output.writeFully(byteArrayOf(1), 0, 1)
                c.output.flush()
                s.input.readExactly(1)
                s.output.writeFully(byteArrayOf(2), 0, 1)
                s.output.flush()
                c.input.readExactly(1)
            } // lets the ticket arrive
            val reused = c.sessionReused && s.sessionReused
            if (exchange) awaitTicket(keyOf(client)) // the ticket lands asynchronously; keep the connection open until it does
            c.close()
            s.close()
            c to reused
        }

    private fun keyOf(client: TlsConfig) = SessionCache.key(client.serverName, "server.test", client.trust, client.identity)

    private suspend fun awaitTicket(key: String): Boolean =
        withTimeoutOrNull(5.seconds) {
            while (!SessionCache.Default.peek(key)) delay(10)
            true
        } ?: false

    private fun stored(key: String): Boolean = runBlocking { awaitTicket(key) }

    @Test fun secondConnectionResumes() {
        val client = TcpFixtures.client()
        val server = TcpFixtures.server()
        val (_, r1) = once(client, server)
        assertTrue(!r1, "first connection is a full handshake")
        val key = SessionCache.key("server.test", "server.test", client.trust, null)
        assertTrue(stored(key), "ticket stored")
        val (c2, r2) = once(client, server)
        assertTrue(r2, "second connection resumes")
        assertEquals(1, c2.peerCertificates.size, "chain comes from the cache on a resumed handshake")
        assertTrue(stored(key), "the resumed connection stored the fresh ticket")
    }

    /**
     * The ticket travels before the data that follows it, so it is cached before the application sees that data: a
     * client that reads one response and closes keeps its ticket (run 38287900994, SocketTlsTest on the macOS runner).
     * The ticket goes into the connection's own cache (an engine's), not into [SessionCache.Default].
     */
    @Test fun ticketCachedBeforeTheDataThatFollowsIt() {
        val client = TcpFixtures.client()
        val key = keyOf(client)
        repeat(100) { round ->
            runBlocking {
                val own = SessionCache()
                val (cd, sd) = connect(client, TcpFixtures.server(), clientCache = own)
                val c = withTimeout(20.seconds) { cd.await() }
                val s = withTimeout(20.seconds) { sd.await() }
                s.output.writeFully(byteArrayOf(2), 0, 1)
                s.output.flush()
                c.input.readExactly(1)
                val cached = own.peek(key)
                c.close()
                s.close()
                own.clear()
                assertTrue(cached, "round $round: the ticket that preceded the data is cached")
                assertEquals(0, SessionCache.Default.size(), "round $round: the ticket stays in the connection's own cache")
            }
        }
    }

    @Test fun ticketIsSingleUse() {
        val client = TcpFixtures.client()
        val server = TcpFixtures.server()
        once(client, server)
        val key = SessionCache.key("server.test", "server.test", client.trust, null)
        assertTrue(stored(key))
        val (_, r2) = once(client, server)
        assertTrue(r2)
        assertTrue(stored(key))
        val (_, r3) = once(client, server)
        assertTrue(r3, "every resumed connection leaves a fresh ticket behind")
        runBlocking { SessionCache.Default.clear() }
        val (_, r4) = once(client, server)
        assertTrue(!r4, "a consumed ticket is never replayed")
    }

    @Test fun cacheKeyIncludesClientIdentity() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val id = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
        val plain = TcpFixtures.client()
        val withId = TcpFixtures.client { identity = id }
        val server =
            TcpFixtures.server {
                clientAuth =
                    ClientAuth.Optional
                ; trust = ca
            }
        once(plain, server)
        val (_, r) = once(withId, server)
        assertTrue(!r, "a client with another identity never resumes the anonymous session")
    }

    @Test fun serverPinnedClientCertResumes() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val id = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
        val client = TcpFixtures.client { identity = id }
        val server =
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust =
                    TrustConfig.Pinned(setOf(Certificate(TestCerts.client).spkiSha256), base = ca)
            }
        val (_, r1) = once(client, server)
        assertTrue(!r1)
        val (_, r2) = once(client, server)
        assertTrue(r2, "pinned client certificate re-checked from the session, handshake resumes")
    }

    /** A resumed handshake carries only the client's leaf, so a CA pin (AnyInValidatedChain) cannot be re-checked; the verdict of the full handshake travels with the ticket. */
    @Test fun serverChainScopePinnedClientResumes() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val client = TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }
        val server =
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust =
                    TrustConfig.Pinned(setOf(Fixtures.testCa.spkiSha256), PinScope.AnyInValidatedChain, ca)
            }
        val (_, r1) = once(client, server)
        assertTrue(!r1)
        val (_, r2) = once(client, server)
        assertTrue(r2, "a client pinned through its CA resumes")
    }

    /** The verdict is bound to the server's trust configuration; a ticket another configuration issued (process-wide ticket keys) is not resumed. */
    @Test fun serverTicketFromOtherTrustConfigNotResumed() {
        val ca = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
        val client = TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }
        once(
            client,
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust = ca
            },
        )
        val pinnedServer =
            TcpFixtures.server {
                clientAuth = ClientAuth.Required
                trust =
                    TrustConfig.Pinned(setOf(Certificate(TestCerts.client).spkiSha256), base = ca)
            }
        val (_, r) = once(client, pinnedServer)
        assertTrue(!r, "full handshake (and pin check) under the other configuration")
    }

    @Test fun negative_resumedSessionRechecksPin() {
        var accept = true
        val verifier =
            CertificateVerifier {
                chain,
                _,
                _,
                ->
                if (accept) VerifyResult.Accepted(chain) else VerifyResult.Rejected(VerifyReason.PinMismatch(chain.map { it.spkiSha256 }))
            }
        val client = TcpFixtures.client { trust = TrustConfig.Custom(verifier) }
        val server = TcpFixtures.server()
        once(client, server)
        accept = false
        runBlocking {
            val (cd, sd) = connect(client, server)
            val e = assertFailsWith<TlsException.Verify> { withTimeout(10.seconds) { cd.await() } }
            assertIs<VerifyReason.PinMismatch>(e.reason)
            runCatching { withTimeout(5.seconds) { sd.await() } }
        }
    }

    @Test fun cacheKeyIncludesTrustConfig() {
        val server = TcpFixtures.server()
        once(TcpFixtures.client(), server)
        val other =
            TcpFixtures.client {
                trust =
                    TrustConfig.Pinned(
                        setOf(Certificate(TestCerts.server).spkiSha256),
                        base = TrustConfig.AnchoredCa(listOf(Fixtures.testCa)),
                    )
            }
        val (c2, r) = once(other, server)
        assertEquals(1, c2.peerCertificates.size)
        assertTrue(!r, "different trust config: no resumption")
        assertTrue(stored(SessionCache.key("server.test", "server.test", other.trust, null)))
    }
}
