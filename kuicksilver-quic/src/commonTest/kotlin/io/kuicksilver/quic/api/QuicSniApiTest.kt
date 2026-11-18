// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TestCerts
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.EndpointLoop
import io.kuicksilver.quic.sniSelectedFor
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.ClientHelloInfo
import io.kuicksilver.tls.EarlyDataState
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.QuicCrypto
import io.kuicksilver.tls.QuicTlsSession
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.SniSelection
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
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
import kotlin.time.Duration.Companion.seconds

/**
 * A QUIC server endpoint with an `sniSelector` (RFC 6066 section 3): the selector runs off the connection loop while the
 * handshake waits, its identity answers the ClientHello, and its refusals close the connection with the TLS alert as
 * CRYPTO_ERROR (RFC 9001 section 4.8: 0x0100 + alert). Invariant: a connection presents exactly the identity chosen for its
 * ClientHello, nothing of a handshake whose connection ended stays allocated, and Retry and 0-RTT work as without it.
 */
@OptIn(ExperimentalAtomicApi::class)
class QuicSniApiTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val leafA = Certificate(TestCerts.server)
    private val leafB = Certificate(TestCerts.proxy)
    private val leafA2 = Certificate(TestCerts.serverOtherKey)

    private fun a() = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    private fun b() = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())

    private fun aOtherKey() = TlsIdentity.fromDer(listOf(TestCerts.serverOtherKey), TestCerts.serverOtherKeyKey.copyOf())

    /** Untrusted by the client: a handshake that completes presented an override. */
    private fun untrusted() = TlsIdentity.fromDer(listOf(TestCerts.serverOtherCa), TestCerts.serverOtherCaKey.copyOf())

    private fun serverTls(
        default: TlsIdentity? = untrusted(),
        selector: suspend (ClientHelloInfo) -> ServerTlsOverride?,
    ): TlsConfig =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("hq-interop")
            identity = default
            sniSelector = selector
        }

    private fun clientConfig(
        name: String = "server.test",
        early: EarlyDataState = EarlyDataState.Disabled,
        handshake: kotlin.time.Duration = 5.seconds,
    ) = QuicClientConfig
        .Builder(CoreFixtures.client(name = name))
        .apply {
            earlyData = early
            quic = quicConfig { handshakeTimeout = handshake }
        }.build()

    private suspend fun QuicConnection.echo(text: String): String {
        val s = openBidi()
        s.output.writeFully(text.encodeToByteArray())
        s.output.flushAndClose()
        val b = ByteArray(4096)
        var out = ""
        while (true) {
            val n = s.input.readAvailable(b, 0, b.size)
            if (n < 0) return out
            out += b.decodeToString(0, n)
        }
    }

    private suspend fun QuicConnection.serveEcho() {
        val s = acceptStream()
        val b = ByteArray(4096)
        var got = ""
        while (true) {
            val n = s.input.readAvailable(b, 0, b.size)
            if (n < 0) break
            got += b.decodeToString(0, n)
        }
        s.output.writeFully("$got!".encodeToByteArray())
        s.output.flushAndClose()
    }

    @Test fun eachNameGetsItsIdentityThroughTheEndpoint(): Unit =
        runBlocking {
            val ids = mapOf("server.test" to a(), "proxy.internal" to b())
            val tls = serverTls { h -> ids[h.serverName]?.let { ServerTlsOverride(it) } }
            ApiPair.open(crypto = KslQuicCrypto, serverTls = tls).use { p ->
                withTimeout(20.seconds) {
                    for ((name, leaf) in listOf("server.test" to leafA, "proxy.internal" to leafB, "server.test" to leafA)) {
                        val accepted = async { p.server.accept().also { it.serveEcho() } }
                        val c = p.client.connect(p.server.localAddress, clientConfig(name))
                        assertEquals("$name!", c.echo(name))
                        val s = accepted.await()
                        assertEquals(leaf, c.peerCertificates[0], name)
                        assertEquals(leaf, s.localCertificates[0], name)
                        assertEquals(name, s.sniSelectedFor)
                        c.close()
                    }
                }
            }
        }

    /** An address as the server name: no SNI (RFC 6066 section 3), the default identity answers. */
    @Test fun noSniTakesTheDefaultIdentity(): Unit =
        runBlocking {
            val seen = CompletableDeferred<String?>()
            val tls =
                serverTls(default = a()) { h ->
                    seen.complete(h.serverName)
                    null
                }
            ApiPair.open(crypto = KslQuicCrypto, serverTls = tls).use { p ->
                withTimeout(20.seconds) {
                    val accepted = async { p.server.accept() }
                    val c = p.client.connect(p.server.localAddress, clientConfig("127.0.0.1"))
                    val s = accepted.await()
                    assertNull(seen.await())
                    assertEquals(leafA, c.peerCertificates[0])
                    assertNull(s.sniSelectedFor)
                    c.close()
                }
            }
        }

    private suspend fun closeCodeOf(
        tls: TlsConfig,
        name: String,
    ): QuicException.ConnectionLost.TransportClosed =
        ApiPair.open(crypto = KslQuicCrypto, serverTls = tls).use { p ->
            withTimeout(20.seconds) {
                assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                    p.client.connect(p.server.localAddress, clientConfig(name))
                }
            }
        }

    /** RFC 6066 section 3: a fatal unrecognized_name, carried as CRYPTO_ERROR 0x170. */
    @Test fun negative_unknownNameClosesWithUnrecognizedName(): Unit =
        runBlocking {
            val e = closeCodeOf(serverTls(default = a()) { null }, "server.test")
            assertEquals(0x100L + 112, e.code)
            assertEquals(Initiator.Peer, e.initiator)
        }

    /** RFC 9846 section 9.2: no SNI and no identity to answer with: missing_extension, CRYPTO_ERROR 0x16d. */
    @Test fun negative_noSniWithoutDefaultIdentityClosesWithMissingExtension(): Unit =
        runBlocking {
            val e = closeCodeOf(serverTls(default = null) { h -> if (h.serverName != null) ServerTlsOverride(a()) else null }, "127.0.0.1")
            assertEquals(0x100L + 109, e.code)
        }

    /** A failing selector closes with internal_error (0x150); the reason phrase the client reads is not the application's text. */
    @Test fun negative_selectorFailureClosesWithInternalError(): Unit =
        runBlocking {
            val e = closeCodeOf(serverTls { throw IllegalStateException("secret detail") }, "server.test")
            assertEquals(0x100L + 80, e.code)
            assertFalse("secret detail" in e.reason, e.reason)
        }

    /** The selector suspends off the loop: a handshake waiting for it holds up no other connection. */
    @Test fun aSuspendedSelectorHoldsUpOnlyItsOwnHandshake(): Unit =
        runBlocking {
            val gate = CompletableDeferred<Unit>()
            val tls =
                serverTls { h ->
                    if (h.serverName == "server.test") gate.await()
                    when (h.serverName) {
                        "server.test" -> ServerTlsOverride(a())
                        else -> ServerTlsOverride(b())
                    }
                }
            ApiPair.open(crypto = KslQuicCrypto, serverTls = tls).use { p ->
                withTimeout(20.seconds) {
                    val waiting = async { p.client.connect(p.server.localAddress, clientConfig("server.test")) }
                    val other = p.client.connect(p.server.localAddress, clientConfig("proxy.internal"))
                    assertEquals(leafB, other.peerCertificates[0], "the other name completed meanwhile")
                    assertFalse(waiting.isCompleted)
                    gate.complete(Unit)
                    assertEquals(leafA, waiting.await().peerCertificates[0])
                }
            }
        }

    /** [KslQuicCrypto], telling [made] about every selection a server session made (the selection is built when it returns). */
    private class SelectionsSeen : QuicCrypto by KslQuicCrypto {
        val made = Channel<SniSelection>(Channel.UNLIMITED)

        private fun wrap(s: QuicTlsSession): QuicTlsSession =
            object : QuicTlsSession by s {
                override suspend fun selectSni(clientHello: ClientHelloInfo): SniSelection =
                    s.selectSni(clientHello).also { made.trySend(it) }
            }

        override fun newSession(config: TlsConfig): QuicTlsSession = wrap(KslQuicCrypto.newSession(config))

        override fun newSession(
            config: TlsConfig,
            earlyData: Boolean,
        ): QuicTlsSession = wrap(KslQuicCrypto.newSession(config, earlyData))
    }

    /**
     * The connection ends (handshake timeout) while its selector runs: the selector is cancelled; one that ignores the
     * cancellation and answers later has its selection closed, so the context built for its identity is freed (and no
     * handshake goes on with it).
     */
    @Test fun negative_aHandshakeThatEndsWhileItsSelectorRunsLeavesNothing(): Unit =
        runBlocking {
            val cancelled = CompletableDeferred<Unit>()
            val stubbornAsked = CompletableDeferred<Unit>()
            val stubborn = CompletableDeferred<Unit>()
            val id = a()
            val tls =
                serverTls(default = id) { h ->
                    if (h.serverName == "server.test") {
                        try {
                            awaitCancellation()
                        } catch (e: CancellationException) {
                            cancelled.complete(Unit)
                            throw e
                        }
                    }
                    if (h.serverName == "proxy.internal") {
                        withContext(NonCancellable) {
                            stubbornAsked.complete(Unit)
                            stubborn.await()
                        }
                    }
                    ServerTlsOverride(id)
                }
            val crypto = SelectionsSeen()
            val shortHandshake = quicConfig { handshakeTimeout = 1.seconds }
            ApiPair.open(crypto = crypto, serverTls = tls, serverQuic = shortHandshake).use { p ->
                withTimeout(30.seconds) {
                    assertFailsWith<QuicException.ConnectionLost> {
                        p.client.connect(p.server.localAddress, clientConfig("server.test", handshake = 2.seconds))
                    }
                    cancelled.await()
                    val late =
                        async {
                            runCatching {
                                p.client.connect(
                                    p.server.localAddress,
                                    clientConfig("proxy.internal", handshake = 2.seconds),
                                )
                            }
                        }
                    stubbornAsked.await()
                    assertTrue(late.await().isFailure, "the handshake ended before its selector answered")
                    stubborn.complete(Unit)
                    val selection = crypto.made.receive() // built after the end of its connection
                    assertTrue(selection.serverName == "proxy.internal")
                    // the runtime closes it on the loop: wait for that, never sleep (a leak never gets there: the timeout fails)
                    while (!selection.isConsumed) yield()
                    assertTrue(crypto.made.tryReceive().isFailure, "no other selection was made")
                }
            }
        }

    /** A Retry (RFC 9000 section 8.1) comes before any TLS session: the selector runs once, for the validated Initial. */
    @Test fun retryIsUnaffected(): Unit =
        runBlocking {
            val asked = AtomicInt(0)
            val tls =
                serverTls { h ->
                    asked.incrementAndFetch()
                    if (h.serverName == "server.test") ServerTlsOverride(a()) else null
                }
            ApiPair.open(crypto = KslQuicCrypto, serverTls = tls, admission = ConnectionAdmission.AlwaysRetry).use { p ->
                withTimeout(20.seconds) {
                    val accepted = async { p.server.accept() }
                    val c = p.client.connect(p.server.localAddress, clientConfig("server.test"))
                    accepted.await()
                    assertEquals(leafA, c.peerCertificates[0])
                    assertEquals(1, asked.load(), "one selection, for the Initial that followed the Retry")
                    c.close()
                }
            }
        }

    // ---- 0-RTT (RFC 9001 section 4.6): accepted under the same identity, rejected under another ----

    private suspend fun ticketFrom(
        p: ApiPair,
        name: String,
    ) {
        coroutineScope {
            val served = async { p.server.accept().serveEcho() }
            val first = p.client.connect(p.server.localAddress, clientConfig(name, EarlyDataState.Allowed))
            assertEquals("one!", first.echo("one"))
            val sessions = (p.client as EndpointLoop).sessions
            while (sessions.size() == 0) yield() // the ticket arrives after the handshake
            first.close()
            served.await()
        }
    }

    /**
     * Accepted: the server hands the connection out at 0-RTT acceptance, before the handshake completes, and it already
     * reports the chosen identity (the authority check of the requests it serves early reads it).
     */
    @Test fun zeroRttAcceptedUnderTheChosenIdentity(): Unit =
        runBlocking {
            val tls = serverTls { h -> if (h.serverName == "server.test") ServerTlsOverride(a()) else null }
            ApiPair.open(crypto = KslQuicCrypto, serverTls = tls, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    ticketFrom(p, "server.test")
                    val early = async { p.server.accept() }
                    p.net.hold(p.clientIo.localAddress) // the client's Finished waits: the server accepts on 0-RTT alone
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig("server.test", EarlyDataState.Allowed))
                    val s = second.openBidi()
                    s.output.writeFully("two".encodeToByteArray())
                    s.output.flushAndClose()
                    val sc = early.await()
                    assertEquals(true, sc.earlyDataAccepted)
                    assertEquals(leafA, sc.localCertificates[0], "the chosen identity, before the handshake completed")
                    assertEquals("server.test", sc.sniSelectedFor)
                    p.net.release(p.clientIo.localAddress)
                    second.awaitHandshake()
                    assertEquals(true, second.earlyDataAccepted)
                    second.close()
                }
            }
        }

    /** Accepted through a Retry (RFC 9000 section 8.1): the selection is made for the Initial after it, 0-RTT still accepted. */
    @Test fun zeroRttThroughARetryUnderTheChosenIdentity(): Unit =
        runBlocking {
            val asked = AtomicInt(0)
            val tls =
                serverTls { h ->
                    asked.incrementAndFetch()
                    if (h.serverName == "server.test") ServerTlsOverride(a()) else null
                }
            val retry = ConnectionAdmission.AlwaysRetry
            ApiPair.open(crypto = KslQuicCrypto, serverTls = tls, serverEarlyData = true, admission = retry).use { p ->
                withTimeout(20.seconds) {
                    ticketFrom(p, "server.test")
                    val served = async { p.server.accept().serveEcho() }
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig("server.test", EarlyDataState.Allowed))
                    assertEquals("two!", second.echo("two"))
                    second.awaitHandshake()
                    assertEquals(true, second.earlyDataAccepted)
                    assertEquals(leafA, second.peerCertificates[0])
                    assertEquals(2, asked.load(), "one selection per connection, none for a Retry")
                    served.await()
                    second.close()
                }
            }
        }

    /**
     * Lost before the server's answer: the client sends 0-RTT while the selector of its handshake still runs, and the server's
     * handshake times out first. The early stream fails with the connection, the selection made afterwards is closed, and the
     * endpoint serves the next client.
     */
    @Test fun negative_zeroRttConnectionLostWhileTheSelectorRuns(): Unit =
        runBlocking {
            val calls = AtomicInt(0)
            val gate = CompletableDeferred<Unit>()
            val tls =
                serverTls { h ->
                    // the second connection's selector outlives its handshake
                    if (calls.incrementAndFetch() == 2) withContext(NonCancellable) { gate.await() }
                    if (h.serverName == "server.test") ServerTlsOverride(a()) else null
                }
            val crypto = SelectionsSeen()
            ApiPair
                .open(
                    crypto = crypto,
                    serverTls = tls,
                    serverEarlyData = true,
                    serverQuic = quicConfig { handshakeTimeout = 1.seconds },
                ).use { p ->
                    withTimeout(30.seconds) {
                        ticketFrom(p, "server.test")
                        crypto.made.receive()
                        val second =
                            p.client.connectEarly(
                                p.server.localAddress,
                                clientConfig("server.test", EarlyDataState.Allowed, 2.seconds),
                            )
                        val s = second.openBidi()
                        s.output.writeFully("early".encodeToByteArray())
                        s.output.flushAndClose()
                        assertFailsWith<QuicException.ConnectionLost> { second.awaitHandshake() }
                        gate.complete(Unit)
                        val late = crypto.made.receive()
                        while (!late.isConsumed) yield() // closed on the loop: wait for it, never sleep
                        val served = async { p.server.accept().serveEcho() }
                        val third = p.client.connect(p.server.localAddress, clientConfig("server.test"))
                        assertEquals("three!", third.echo("three"))
                        served.await()
                        third.close()
                    }
                }
        }

    /** Rejected: the selector now answers with another certificate for the same name; the ticket's 0-RTT is refused. */
    @Test fun negative_zeroRttRejectedUnderAnotherIdentity(): Unit =
        runBlocking {
            var current = a()
            val tls = serverTls { h -> if (h.serverName == "server.test") ServerTlsOverride(current) else null }
            ApiPair.open(crypto = KslQuicCrypto, serverTls = tls, serverEarlyData = true).use { p ->
                withTimeout(20.seconds) {
                    ticketFrom(p, "server.test")
                    current = aOtherKey()
                    val served = async { p.server.accept().serveEcho() }
                    val second = p.client.connectEarly(p.server.localAddress, clientConfig("server.test", EarlyDataState.Allowed))
                    second.awaitHandshake()
                    assertEquals(false, second.earlyDataAccepted, "a ticket of the other certificate gets no 0-RTT")
                    assertEquals(leafA2, second.peerCertificates[0], "a full handshake with the new certificate")
                    assertEquals("after!", second.echo("after"))
                    served.await()
                    second.close()
                }
            }
        }
}
