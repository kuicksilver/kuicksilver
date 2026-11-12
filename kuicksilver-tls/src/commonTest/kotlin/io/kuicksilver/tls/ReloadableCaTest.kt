// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * [TrustConfig.ReloadableCa]: rotating the CA bundle a server verifies client certificates with. Handshakes that start after
 * a reload verify against the new bundle; a handshake already started and established connections keep the bundle they
 * started with; a session from before the reload is not resumed (RFC 9846 section 4.7.1: "A server MAY treat a ticket as
 * valid for a shorter period"), so a client whose CA was dropped cannot resume its way back in.
 */
class ReloadableCaTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val testCa = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
    private val otherCa = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa)))

    /** A client certificate issued by the test CA. */
    private fun clientA() = TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) }

    /** A client certificate issued by the other CA. */
    private fun clientB() =
        TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.clientOtherCa), TestCerts.clientOtherCaKey.copyOf()) }

    private fun server(trust: TrustConfig) =
        TcpFixtures.server {
            clientAuth = ClientAuth.Required
            this.trust = trust
        }

    private suspend fun open(
        client: TlsConfig,
        server: TlsConfig,
        cache: SessionCache = SessionCache(),
    ): Pair<TlsConnection, TlsConnection> {
        val (cd, sd) = connect(client, server, clientCache = cache)
        return withTimeout(20.seconds) { cd.await() to sd.await() }
    }

    /** The server side of a handshake that must fail on the client certificate, with the reason. */
    private suspend fun refused(
        client: TlsConfig,
        server: TlsConfig,
        cache: SessionCache = SessionCache(),
    ): VerifyReason {
        val (cd, sd) = connect(client, server, clientCache = cache)
        val e = assertFailsWith<TlsException.Verify> { withTimeout(20.seconds) { sd.await() } }
        runCatching { withTimeout(20.seconds) { cd.await() }.close() }
        return e.reason
    }

    private suspend fun exchange(
        c: TlsConnection,
        s: TlsConnection,
    ) {
        val up = ByteArray(512) { it.toByte() }
        withTimeout(20.seconds) {
            c.output.writeFully(up, 0, up.size)
            c.output.flush()
            assertContentEquals(up, s.input.readExactly(up.size))
            s.output.writeFully(up, 0, up.size)
            s.output.flush()
            assertContentEquals(up, c.input.readExactly(up.size))
        }
    }

    @Test fun newHandshakesVerifyAgainstTheReloadedBundle(): Unit =
        runBlocking {
            val r = TrustConfig.reloadable(testCa)
            val server = server(r)
            val (c1, s1) = open(clientA(), server)
            assertEquals(Certificate(TestCerts.client), s1.peerCertificates[0])
            assertIs<VerifyReason.UnknownIssuer>(refused(clientB(), server), "control: the other CA is not trusted yet")
            r.reload(otherCa)
            assertSame(otherCa, r.current)
            val (c2, s2) = open(clientB(), server)
            assertEquals(Certificate(TestCerts.clientOtherCa), s2.peerCertificates[0], "the new CA's client is accepted")
            exchange(c1, s1) // the connection from before the reload goes on
            exchange(c2, s2)
            listOf(c1, s1, c2, s2).forEach { it.close() }
        }

    @Test fun negative_oldCaRejectedAfterReload(): Unit =
        runBlocking {
            val r = TrustConfig.reloadable(testCa)
            val server = server(r)
            val (c, s) = open(clientA(), server)
            c.close()
            s.close()
            r.reload(otherCa)
            assertIs<VerifyReason.UnknownIssuer>(refused(clientA(), server), "a client of the dropped CA is refused")
        }

    /**
     * A TCP connection accepted before a reload whose ClientHello arrives after it is verified against the new bundle: the
     * bundle is taken when the ClientHello is there, not at accept, so a client of a dropped CA cannot connect early and
     * send its hello late.
     */
    @Test fun negative_connectionAcceptedBeforeReloadUsesTheBundleOfItsClientHello(): Unit =
        runBlocking(Dispatchers.Default) {
            val r = TrustConfig.reloadable(testCa)
            val server = server(r)
            val pair = ChannelPair()
            // undispatched: the server runs until it waits for the ClientHello, which has not been sent
            val sd =
                async(start = CoroutineStart.UNDISPATCHED) { runCatching { TlsConnection.server(pair.serverIn, pair.serverOut, server) } }
            r.reload(otherCa)
            val cd =
                async {
                    runCatching {
                        TlsConnection.client(
                            pair.clientIn,
                            pair.clientOut,
                            clientA(),
                            EmptyCoroutineContext,
                            SessionCache(),
                        )
                    }
                }
            val e =
                assertIs<TlsException.Verify>(withTimeout(20.seconds) { sd.await() }.exceptionOrNull(), "the old CA's client is refused")
            assertIs<VerifyReason.UnknownIssuer>(e.reason)
            withTimeout(20.seconds) { cd.await() }.getOrNull()?.close()
        }

    /** A handshake whose ClientHello arrived before a reload keeps the bundle it started with while the reload happens. */
    @Test fun handshakeInProgressKeepsItsBundle(): Unit =
        runBlocking(Dispatchers.Default) {
            val r = TrustConfig.reloadable(testCa)
            val server = server(r)
            val pair = ChannelPair()
            val cd = async { TlsConnection.client(pair.clientIn, pair.clientOut, clientA(), EmptyCoroutineContext, SessionCache()) }
            withTimeout(20.seconds) { pair.serverIn.awaitContent(1) } // the ClientHello is on its way
            // undispatched: with the hello there the server takes its context (and the bundle) before this returns
            val sd = async(start = CoroutineStart.UNDISPATCHED) { TlsConnection.server(pair.serverIn, pair.serverOut, server) }
            r.reload(otherCa)
            val (c, s) = withTimeout(20.seconds) { cd.await() to sd.await() }
            assertEquals(Certificate(TestCerts.client), s.peerCertificates[0], "verified against the bundle of its ClientHello")
            exchange(c, s)
            c.close()
            s.close()
            assertIs<VerifyReason.UnknownIssuer>(refused(clientA(), server), "the next handshake uses the new bundle")
        }

    /**
     * Sessions are keyed by the bundle's certificates, not only their keys: a CA re-issued on the same key (here with a path
     * length constraint added) is another bundle, so a ticket from before the reload is not resumed under it.
     */
    @Test fun negative_caReissuedOnTheSameKeyVoidsTickets(): Unit =
        runBlocking {
            val ca1 = Certificate(ReissuedCaCerts.ca1)
            val ca2 = Certificate(ReissuedCaCerts.ca2)
            assertEquals(ca1.spkiSha256, ca2.spkiSha256, "control: one key")
            val r = TrustConfig.reloadable(TrustConfig.AnchoredCa(listOf(ca1)))
            val server = server(r)
            val client =
                TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(ReissuedCaCerts.client), ReissuedCaCerts.clientKey.copyOf()) }
            val cache = SessionCache()
            val (c0, s0) = open(client, server, cache)
            exchange(c0, s0)
            c0.close()
            s0.close()
            val (c1, s1) = open(client, server, cache)
            assertTrue(c1.sessionReused && s1.sessionReused, "control: the ticket resumes under the same bundle")
            exchange(c1, s1)
            c1.close()
            s1.close()
            r.reload(TrustConfig.AnchoredCa(listOf(ca2)))
            val (c2, s2) = open(client, server, cache)
            assertTrue(!c2.sessionReused && !s2.sessionReused, "the re-issued CA is another bundle")
            c2.close()
            s2.close()
        }

    /** The registry never takes a context of a bundle replaced while it was built: it serves its handshake unshared. */
    @Test fun contextBuiltAcrossAReloadIsNotShared() {
        val r = TrustConfig.reloadable(testCa)
        val config =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
                clientAuth = ClientAuth.Required
                trust = r
            }
        val registry = SharedServerContexts()
        val read = r.current // the bundle the handshake read before the reload
        val made =
            registry.acquire(config, quic = true, quicTickets = false, earlyData = false, ca = read) {
                r.reload(otherCa) // lands while the context is built
                KslContext.create(config, quic = true).ctx // one reference: the builder's
            }!!
        val next = registry.acquire(config, true, false, false, r.current) { KslContext.create(config, quic = true).ctx }!!
        assertNotSame(made, next, "the context built across the reload was not registered")
        made.release()
        assertTrue(made.isFreed, "freed with its handshake: the registry holds no reference")
        next.release()
        assertFalse(next.isFreed, "the current bundle's context is kept")
        registry.close()
        assertTrue(next.isFreed)
        config.identity.let { (it as TlsIdentity.InMemory).close() }
    }

    /**
     * A ticket from before a reload resumes nothing: the client runs a full handshake and its certificate is verified
     * against the new bundle. With the client's CA dropped, its ticket does not get it back in.
     */
    @Test fun negative_ticketIssuedBeforeCaReloadIsNotResumed(): Unit =
        runBlocking {
            val r = TrustConfig.reloadable(testCa)
            val server = server(r)
            val cache = SessionCache()
            val (c0, s0) = open(clientA(), server, cache)
            exchange(c0, s0) // the server's tickets travel before its data
            c0.close()
            s0.close()
            val (c1, s1) = open(clientA(), server, cache)
            assertTrue(c1.sessionReused && s1.sessionReused, "control: before the reload the ticket resumes")
            exchange(c1, s1)
            c1.close()
            s1.close()
            r.reload(TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa), Certificate(TestCerts.otherCa))))
            val (c2, s2) = open(clientA(), server, cache)
            assertTrue(!c2.sessionReused && !s2.sessionReused, "a ticket from before the reload is not resumed")
            exchange(c2, s2)
            c2.close()
            s2.close()
            val (c3, s3) = open(clientA(), server, cache)
            assertTrue(c3.sessionReused && s3.sessionReused, "a ticket issued under the new bundle resumes")
            exchange(c3, s3)
            c3.close()
            s3.close()
            r.reload(otherCa)
            assertIs<VerifyReason.UnknownIssuer>(refused(clientA(), server, cache), "the cached ticket does not let the old CA's client in")
        }

    /**
     * A reload drops the server's shared context of the old bundle (QUIC sessions here: they release their context when
     * closed, synchronously): it serves the connections that hold it and is freed with the last of them.
     */
    @Test fun reloadReplacesTheSharedContext() {
        val r = TrustConfig.reloadable(testCa)
        val id = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        val config =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity = id
                clientAuth = ClientAuth.Required
                trust = r
            }

        fun session() = KslQuicCrypto.newSession(config) as KslQuicTlsSession
        val a1 = session()
        val a2 = session()
        val ctxA = a1.context
        assertSame(ctxA, a2.context, "one context per bundle, shared")
        r.reload(otherCa)
        val b = session()
        assertNotSame(ctxA, b.context, "the first handshake after the reload builds one with the new bundle")
        assertSame(otherCa, b.context.trustSnapshot)
        assertSame(b.context, session().also { it.close() }.context, "and the next ones share it")
        a1.close()
        assertFalse(ctxA.isFreed, "the old context serves its last connection")
        a2.close()
        assertTrue(ctxA.isFreed, "and goes with it: the registry let go of it at the reload")
        b.close()
        assertFalse(b.context.isFreed, "the current bundle's context is kept for the next handshake")
        id.close()
        assertTrue(b.context.isFreed)
    }

    @Test fun negative_bundleWithoutAValidCertificateRefused() {
        var now = nowSeconds()
        val ca = Certificate(TestCerts.testCa)
        val r = TrustConfig.ReloadableCa(testCa) { now }
        val expired = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.expired)))
        val e = assertFailsWith<TlsException.Config> { r.reload(expired) }
        assertTrue("no certificate" in e.message.orEmpty(), e.message)
        assertSame(testCa, r.current, "the bundle in use stays")
        val notYet = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.notYetValid)))
        assertFailsWith<TlsException.Config> { r.reload(notYet) }
        // one valid certificate is enough: an expired one beside it never anchors a chain anyway
        val mixed = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.expired), ca))
        r.reload(mixed)
        assertSame(mixed, r.current)
        now = ca.notAfterEpochSeconds + 1
        assertFailsWith<TlsException.Config>("on the clock of the bundle") { r.reload(testCa) }
        assertFailsWith<TlsException.Config>("not a starting point either") { TrustConfig.reloadable(expired) }
    }

    /** basicConstraints `cA` as the bundle warnings read it: CA certificates true, leaves false. */
    @Test fun caFlagOfCertificates() {
        assertTrue(Certificate(TestCerts.testCa).isCa)
        assertTrue(Certificate(TestCerts.otherCa).isCa)
        assertTrue(Certificate(TestCerts.intermediate).isCa)
        assertTrue(Certificate(ReissuedCaCerts.ca2).isCa, "with a path length")
        assertFalse(Certificate(TestCerts.client).isCa)
        assertFalse(Certificate(TestCerts.server).isCa)
    }

    @Test fun negative_clientConfigurationRefusesReloadableCa() {
        val r = TrustConfig.reloadable(testCa)
        assertFailsWith<TlsException.Config> { TcpFixtures.client { trust = r } }
        assertFailsWith<TlsException.Config> {
            TcpFixtures.client { trust = TrustConfig.Pinned(setOf(Certificate(TestCerts.client).spkiSha256), base = r) }
        }
        assertFailsWith<TlsException.Config>("ExpectedName takes Platform, AnchoredCa or Custom") {
            TrustConfig.ExpectedName("server.test", r)
        }
    }

    @Test fun pinnedOverReloadableCaChecksPinsAndTheCurrentBundle(): Unit =
        runBlocking {
            val r = TrustConfig.reloadable(testCa)
            val server = server(TrustConfig.Pinned(setOf(Certificate(TestCerts.clientOtherCa).spkiSha256), base = r))
            assertIs<VerifyReason.UnknownIssuer>(refused(clientB(), server), "pinned but not under the bundle")
            r.reload(otherCa)
            val (c, s) = open(clientB(), server)
            assertEquals(Certificate(TestCerts.clientOtherCa), s.peerCertificates[0])
            c.close()
            s.close()
            r.reload(TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa), Certificate(TestCerts.otherCa))))
            assertIs<VerifyReason.PinMismatch>(refused(clientA(), server), "under the bundle but not pinned")
        }
}
