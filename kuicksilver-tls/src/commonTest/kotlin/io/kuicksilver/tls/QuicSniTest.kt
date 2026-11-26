// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A QUIC server's `sniSelector` (RFC 6066 section 3): the handshake pauses at the ClientHello ([DriveResult.WantSni]), the
 * selection runs as a connection runtime runs it ([QuicTlsSession.selectSni], then [QuicTlsSession.resumeSni]), and the
 * chosen identity's chain, key and settings answer it. Invariant: every completed handshake presents exactly the identity
 * the selector chose for its ClientHello (the default one without an answer and without SNI), and a session ticket or its
 * 0-RTT is only ever accepted under the server name and the certificate it was issued under.
 */
class QuicSniTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** server.test (and 127.0.0.1), trusted by the client. */
    private val a = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())

    /** proxy.internal, trusted by the client. */
    private val b = TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf())

    /** server.test again, under another key: the same name, another certificate. */
    private val aOtherKey = TlsIdentity.fromDer(listOf(TestCerts.serverOtherKey), TestCerts.serverOtherKeyKey.copyOf())

    /** The default identity: server.test from a CA the client does not trust, so a completed handshake proves an override. */
    private val untrusted = TlsIdentity.fromDer(listOf(TestCerts.serverOtherCa), TestCerts.serverOtherCaKey.copyOf())

    private fun server(
        default: TlsIdentity? = untrusted,
        selector: suspend (ClientHelloInfo) -> ServerTlsOverride?,
    ): TlsConfig =
        tlsConfig(TlsRole.Server) {
            alpn = listOf("h3")
            identity = default
            sniSelector = selector
        }

    private fun byName(vararg ids: Pair<String, TlsIdentity>): suspend (ClientHelloInfo) -> ServerTlsOverride? =
        { h -> h.serverName?.let { n -> ids.firstOrNull { it.first == n }?.second }?.let { ServerTlsOverride(it) } }

    private fun pump(
        client: QuicTlsSession,
        server: QuicTlsSession,
    ): Pump {
        client.setTransportParameters(Fixtures.tp)
        server.setTransportParameters(Fixtures.tp)
        return Pump(client, server).also { it.run() }
    }

    private fun handshake(
        client: TlsConfig,
        server: TlsConfig,
    ): Pump = pump(KslQuicCrypto.newSession(client), KslQuicCrypto.newSession(server))

    private fun leaf(id: TlsIdentity): Certificate = (id as TlsIdentity.InMemory).chain[0]

    private fun liveContexts(): Long = Ksl.liveObjects()[KslConst.LIVE_CTX]

    @Test fun sniSelectorChoosesTheIdentityPerName() {
        for ((name, id) in listOf("server.test" to a, "proxy.internal" to b)) {
            val p = handshake(Fixtures.client(name = name), server(selector = byName("server.test" to a, "proxy.internal" to b)))
            try {
                assertTrue(p.cs.done && p.ss.done, "$name: ${p.cs.last} / ${p.ss.last}")
                assertEquals(leaf(id), p.c.peerCertificates[0], "$name: the client saw the chosen identity")
                assertEquals(leaf(id), p.s.localCertificates[0], "$name: the server reports the chosen identity")
                assertEquals(name, p.s.sniSelectedFor)
                assertEquals("h3", p.s.negotiatedAlpn)
            } finally {
                p.close()
            }
        }
    }

    @Test fun theSelectorSeesTheClientHello() {
        val seen = ArrayList<ClientHelloInfo>()
        val c = KslQuicCrypto.newSession(Fixtures.client { alpn = listOf("h3", "hq-interop") })
        val s = KslQuicCrypto.newSession(server(selector = byName("server.test" to a)))
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        val p = Pump(c, s)
        p.onSni = { seen += it }
        p.run()
        try {
            assertTrue(p.cs.done && p.ss.done)
            assertEquals(1, seen.size, "one pause per handshake")
            assertEquals("server.test", seen[0].serverName)
            assertEquals(listOf("h3", "hq-interop"), seen[0].alpn)
            assertTrue(0x0403 in seen[0].signatureSchemes, "ecdsa_secp256r1_sha256 offered: ${seen[0].signatureSchemes}")
        } finally {
            p.close()
        }
    }

    /** RFC 6066 section 3: a ClientHello for an address carries no server_name; the selector sees null and the default answers. */
    @Test fun noSniUsesTheDefaultIdentity() {
        val names = ArrayList<String?>()
        val p =
            handshake(
                Fixtures.client(name = "127.0.0.1"),
                server(default = a) { h ->
                    names += h.serverName
                    null
                },
            )
        try {
            assertTrue(p.cs.done && p.ss.done, "${p.cs.last} / ${p.ss.last}")
            assertEquals(listOf<String?>(null), names)
            assertNull(p.s.sniSelectedFor)
            assertEquals(leaf(a), p.s.localCertificates[0])
        } finally {
            p.close()
        }
    }

    /** RFC 6066 section 3: a name the selector does not serve ends the handshake with a fatal unrecognized_name (112). */
    @Test fun negative_unknownNameEndsWithUnrecognizedName() {
        val p = handshake(Fixtures.client(name = "server.test"), server(default = a, selector = byName("proxy.internal" to b)))
        try {
            assertEquals(112, assertIs<DriveResult.Failed>(p.ss.last).alert)
            assertFalse(p.ss.done)
        } finally {
            p.close()
        }
    }

    /** RFC 9846 section 9.2: no server_name, no answer and no default identity: missing_extension (109). */
    @Test fun negative_noSniWithoutDefaultIdentityEndsWithMissingExtension() {
        val p = handshake(Fixtures.client(name = "127.0.0.1"), server(default = null, selector = byName("server.test" to a)))
        try {
            assertEquals(109, assertIs<DriveResult.Failed>(p.ss.last).alert)
        } finally {
            p.close()
        }
    }

    /** No default identity, but SNI: the selector's identity serves it. */
    @Test fun aServerWithoutDefaultIdentityServesItsNames() {
        val p = handshake(Fixtures.client(name = "proxy.internal"), server(default = null, selector = byName("proxy.internal" to b)))
        try {
            assertTrue(p.cs.done && p.ss.done, "${p.cs.last} / ${p.ss.last}")
            assertEquals(leaf(b), p.c.peerCertificates[0])
        } finally {
            p.close()
        }
    }

    @Test fun negative_selectorFailureEndsWithInternalError() {
        val p = handshake(Fixtures.client(), server { throw IllegalStateException("selector down") })
        try {
            val f = assertIs<DriveResult.Failed>(p.ss.last)
            assertEquals(80, f.alert)
            assertEquals("selector down", f.exception.cause?.message, "the application's failure is the cause")
            assertFalse("selector down" in (f.exception.message ?: ""), "and never the message a QUIC peer reads")
        } finally {
            p.close()
        }
    }

    /** An override QUIC cannot use (no ALPN, RFC 9001 section 8.1) fails that handshake with internal_error and a Config cause. */
    @Test fun negative_overrideUnfitForQuicEndsWithInternalError() {
        val p = handshake(Fixtures.client(), server { ServerTlsOverride(a, alpn = emptyList()) })
        try {
            val f = assertIs<DriveResult.Failed>(p.ss.last)
            assertEquals(80, f.alert)
            assertIs<TlsException.Config>(f.exception.cause)
        } finally {
            p.close()
        }
    }

    /**
     * `alpnFallback` is for TLS over TCP: QUIC needs ALPN anyway (RFC 9001 section 8.1, a client without it is refused in
     * ksl), so a QUIC server with one not in its list neither pauses for it nor refuses an `h3` client, with a selector or
     * without one.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    @Test
    fun aQuicServerIgnoresTheAlpnFallback() {
        val plain =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity = a
                expert { alpnFallback = "http/1.1" }
            }
        val withSelector =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity = untrusted
                sniSelector = { ServerTlsOverride(a, alpn = listOf("h3")) }
                expert { alpnFallback = "http/1.1" }
            }
        for (config in listOf(plain, withSelector)) {
            val p = handshake(Fixtures.client(), config)
            try {
                assertTrue(p.cs.done && p.ss.done, "the handshake completed")
                assertEquals("h3", p.s.negotiatedAlpn)
            } finally {
                p.close()
            }
        }
    }

    @Test fun overrideAlpnReplacesTheList() {
        val p =
            handshake(
                Fixtures.client { alpn = listOf("h3", "hq-interop") },
                server { ServerTlsOverride(a, alpn = listOf("hq-interop")) },
            )
        try {
            assertTrue(p.cs.done && p.ss.done)
            assertEquals("hq-interop", p.c.negotiatedAlpn)
            assertEquals("hq-interop", p.s.negotiatedAlpn)
        } finally {
            p.close()
        }
    }

    private val clientIdentity get() = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
    private val testCaTrust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))

    /** The override's client-certificate policy is the one in effect, its pins included (checked when the handshake completes). */
    @Test fun negative_overrideClientAuthAndPinsAreInEffect() {
        val required = server { ServerTlsOverride(a, clientAuth = ClientAuth.Required, trust = testCaTrust) }
        val withCert = handshake(Fixtures.client { identity = clientIdentity }, required)
        try {
            assertTrue(withCert.cs.done && withCert.ss.done, "control: ${withCert.ss.last}")
            assertEquals(Certificate(TestCerts.client), withCert.s.peerCertificates[0])
        } finally {
            withCert.close()
        }
        val anonymous = handshake(Fixtures.client(), required)
        try {
            assertIs<DriveResult.Failed>(anonymous.ss.last, "the override requires a client certificate")
        } finally {
            anonymous.close()
        }
        val wrongPin = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32))), base = testCaTrust)
        val pinned =
            handshake(
                Fixtures.client {
                    identity = clientIdentity
                },
                server { ServerTlsOverride(a, clientAuth = ClientAuth.Required, trust = wrongPin) },
            )
        try {
            val f = assertIs<DriveResult.Failed>(pinned.ss.last, "the override's pins refuse the client")
            assertIs<VerifyReason.PinMismatch>(assertIs<TlsException.Verify>(f.exception).reason)
            assertFalse(pinned.ss.done)
        } finally {
            pinned.close()
        }
    }

    // ---- tickets and 0-RTT (RFC 6066 section 3, RFC 9846 section 4.7.1, RFC 9001 section 4.6) ----

    private class Admission : EarlyDataAdmission {
        val admitted = ArrayList<ByteArray>()
        val released = ArrayList<ByteArray>()

        override fun admit(ticketId: ByteArray): Boolean {
            admitted += ticketId
            return true
        }

        override fun release(ticketId: ByteArray) {
            released += ticketId
        }
    }

    private class Outcome(
        val pump: Pump,
        val tickets: List<QuicSessionTicket>,
        val admission: Admission,
    ) {
        fun close() {
            tickets.forEach { it.close() }
            pump.close()
        }
    }

    /** One early-data handshake; the client resumes [ticket] with 0-RTT when given. */
    private fun earlyHandshake(
        client: TlsConfig,
        server: TlsConfig,
        ticket: QuicSessionTicket? = null,
    ): Outcome {
        val c = KslQuicCrypto.newSession(client, earlyData = true)
        val s = KslQuicCrypto.newSession(server, earlyData = true)
        val admission = Admission()
        assertTrue(s.enableEarlyData(byteArrayOf(7), admission))
        if (ticket != null) {
            assertTrue(c.resume(ticket), "the client offers the ticket")
            assertTrue(c.enableEarlyData(null, null), "the ticket allows 0-RTT")
        }
        val tickets = ArrayList<QuicSessionTicket>()
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        val p = Pump(c, s)
        p.onEvent = { fromClient, ev -> if (fromClient && ev is TlsEvent.SessionTicket) tickets += ev.ticket }
        p.run()
        return Outcome(p, tickets, admission)
    }

    private fun firstTicket(
        client: TlsConfig,
        server: TlsConfig,
    ): QuicSessionTicket {
        val o = earlyHandshake(client, server)
        assertTrue(o.pump.cs.done && o.pump.ss.done, "${o.pump.cs.last} / ${o.pump.ss.last}")
        assertTrue(o.tickets.isNotEmpty(), "the override's handshake issues tickets")
        o.tickets.drop(1).forEach { it.close() }
        o.pump.close()
        return o.tickets[0]
    }

    @Test fun zeroRttUnderTheSameIdentity() {
        val config = server(selector = byName("server.test" to a))
        val ticket = firstTicket(Fixtures.client(), config)
        val o = earlyHandshake(Fixtures.client(), config, ticket)
        try {
            assertTrue(o.pump.cs.done && o.pump.ss.done)
            assertTrue((o.pump.s as KslQuicTlsSession).sessionReusedForTest, "resumed")
            assertEquals(true, o.pump.s.earlyDataAccepted)
            assertEquals(true, o.pump.c.earlyDataAccepted)
            assertEquals(leaf(a), o.pump.s.localCertificates[0])
        } finally {
            o.close()
        }
    }

    /** RFC 9846 section 4.7.1: the same name, but the selector now picks another certificate: a full handshake, no 0-RTT. */
    @Test fun negative_ticketOfOneIdentityIsNotResumedUnderAnother() {
        val ticket = firstTicket(Fixtures.client(), server(selector = byName("server.test" to a)))
        val o = earlyHandshake(Fixtures.client(), server(selector = byName("server.test" to aOtherKey)), ticket)
        try {
            assertTrue(o.pump.cs.done && o.pump.ss.done, "${o.pump.cs.last} / ${o.pump.ss.last}")
            assertFalse((o.pump.s as KslQuicTlsSession).sessionReusedForTest, "not resumed under the other certificate")
            assertEquals(false, o.pump.s.earlyDataAccepted)
            assertEquals(false, o.pump.c.earlyDataAccepted)
            assertEquals(leaf(aOtherKey), o.pump.c.peerCertificates[0], "the client verified the new certificate")
            assertEquals(o.admission.admitted.size, o.admission.released.size, "the replay register gave the hello back")
        } finally {
            o.close()
        }
    }

    /**
     * RFC 9846 section 4.7.1: clients "SHOULD only resume if the SNI value matches the one used in the original session". A
     * ticket of server.test is not offered to proxy.internal, also when the selector serves both with the same certificate, so
     * no 0-RTT is tried under the other name either (OpenSSL's client would fail that handshake). The server side, a ticket
     * another client offers under another name, is C `negative_session_of_another_server_name_is_not_offered`.
     */
    @Test fun negative_ticketIsNotOfferedUnderAnotherName() {
        val selector = byName("server.test" to a, "proxy.internal" to a)
        val ticket = firstTicket(Fixtures.client(), server(selector = selector))
        val c =
            KslQuicCrypto.newSession(
                Fixtures.client(name = "proxy.internal", trust = TrustConfig.ExpectedName("server.test", testCaTrust)),
                earlyData = true,
            )
        try {
            assertFalse(c.resume(ticket), "another name's ticket is refused")
            assertTrue(ticket.closed, "and released")
            assertFalse(c.enableEarlyData(null, null), "so no 0-RTT")
        } finally {
            c.close()
        }
        val upper = KslQuicCrypto.newSession(Fixtures.client(name = "SERVER.Test"), earlyData = true)
        val again = firstTicket(Fixtures.client(), server(selector = selector))
        try {
            assertTrue(upper.resume(again), "control: the same name in another case (normalized to lower case)")
            assertTrue(upper.enableEarlyData(null, null))
        } finally {
            upper.close()
        }
    }

    /**
     * An override with client certificates on a 0-RTT server: no ticket (one would precede the pin verdict) and no 0-RTT (0-RTT
     * with client certificates is not supported); a ticket of the same identity without client certificates is not resumed
     * under it (another session context).
     */
    @Test fun negative_overrideWithClientCertificatesGetsNoTicketsAndNo0Rtt() {
        val withAuth = server { ServerTlsOverride(a, clientAuth = ClientAuth.Required, trust = testCaTrust) }
        val o = earlyHandshake(Fixtures.client { identity = clientIdentity }, withAuth)
        try {
            assertTrue(o.pump.cs.done && o.pump.ss.done, "${o.pump.cs.last} / ${o.pump.ss.last}")
            assertTrue(o.tickets.isEmpty(), "no ticket under client certificates")
        } finally {
            o.close()
        }
        val ticket = firstTicket(Fixtures.client { identity = clientIdentity }, server(selector = byName("server.test" to a)))
        val r = earlyHandshake(Fixtures.client { identity = clientIdentity }, withAuth, ticket)
        try {
            assertTrue(r.pump.cs.done && r.pump.ss.done, "${r.pump.cs.last} / ${r.pump.ss.last}")
            assertFalse((r.pump.s as KslQuicTlsSession).sessionReusedForTest)
            assertEquals(false, r.pump.s.earlyDataAccepted)
            assertEquals(Certificate(TestCerts.client), r.pump.s.peerCertificates[0], "the full handshake verified the client")
        } finally {
            r.close()
        }
    }

    // ---- the chosen identity's context, shared across handshakes (OverrideConfigs) ----

    private fun overrideContext(p: Pump): KslContext? = (p.s as KslQuicTlsSession).overrideContextForTest

    /** Equal answers share one native context; another ALPN list is another configuration and another context. */
    @Test fun equalAnswersShareTheChosenIdentitysContext() {
        val config = server { h -> ServerTlsOverride(a, alpn = if (h.alpn.size > 1) listOf("hq-interop") else null) }
        val first = handshake(Fixtures.client(), config)
        val second = handshake(Fixtures.client(), config)
        val other = handshake(Fixtures.client { alpn = listOf("h3", "hq-interop") }, config)
        try {
            assertTrue(first.ss.done && second.ss.done && other.ss.done)
            val shared = overrideContext(first)
            assertTrue(shared != null && shared === overrideContext(second), "a new ServerTlsOverride with the same identity: one context")
            assertTrue(overrideContext(other) !== shared, "another ALPN list: another context")
            assertEquals(2, config.overrideConfigs.size)
        } finally {
            first.close()
            second.close()
            other.close()
        }
    }

    /** A reloaded identity reaches the next handshake through the shared context: the registry keys its contexts by snapshot. */
    @Test fun aReloadedIdentityReachesTheNextHandshake() {
        val r = TlsIdentity.reloadable(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()))
        val config = server { ServerTlsOverride(r) }
        val before = handshake(Fixtures.client(), config)
        r.reload(aOtherKey)
        val after = handshake(Fixtures.client(), config)
        try {
            assertEquals(leaf(a), before.c.peerCertificates[0])
            assertEquals(leaf(aOtherKey), after.c.peerCertificates[0], "the new certificate after the reload")
            assertTrue(overrideContext(before) !== overrideContext(after))
        } finally {
            before.close()
            after.close()
            r.close()
        }
    }

    /** A selector that makes a new identity for every handshake keeps no more than [OverrideConfigs.MAX] configurations alive. */
    @Test fun negative_theAnswerCacheIsBounded() {
        val config = server { ServerTlsOverride(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())) }
        val (s, w) = paused(config)
        try {
            repeat(OverrideConfigs.MAX + 10) { runBlocking { s.selectSni(w.clientHello) }.close() }
            assertTrue(config.overrideConfigs.size <= OverrideConfigs.MAX, "${config.overrideConfigs.size}")
        } finally {
            s.close()
        }
    }

    /**
     * Least recently used, not all at once: a hot set of answers keeps hitting while more than [OverrideConfigs.MAX] other
     * answers come and go (the cache used to start over on the 65th answer, and every hot handshake then built its context
     * again).
     */
    @Test fun negative_aHotSetOfAnswersSurvivesManyOthers() {
        val config = server { null }
        val hot = List(8) { i -> ServerTlsOverride(a, alpn = listOf("h3", "x$i")) }
        val first = hot.map { config.overrideConfigs.of(config, it) }
        var hits = 0
        var lookups = 0
        repeat(200) { round ->
            hot.forEachIndexed { i, o ->
                lookups++
                if (config.overrideConfigs.of(config, ServerTlsOverride(o.identity, o.alpn)) === first[i]) hits++
            }
            config.overrideConfigs.of(config, ServerTlsOverride(a, alpn = listOf("h3", "cold$round"))) // a new answer each round
        }
        assertEquals(lookups, hits, "every hot lookup hit")
        assertTrue(config.overrideConfigs.size <= OverrideConfigs.MAX)
    }

    /** Contexts of selector answers never push the server configuration's own contexts out of its identity's registry. */
    @Test fun negative_answersNeverEvictTheBaseConfigurationsContexts() {
        val id = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        // each call a new trust object: a new answer and a new context under the same identity as the base configuration
        val config = server(default = id) { ServerTlsOverride(id, trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))) }
        val base = KslQuicCrypto.newSession(config) as KslQuicTlsSession
        val baseContext = base.context
        base.close()
        val (s, w) = paused(config)
        try {
            repeat(100) { runBlocking { s.selectSni(w.clientHello) }.close() }
        } finally {
            s.close()
        }
        val held = id.serverContexts.contextsForTest()
        assertTrue(baseContext in held, "the base configuration's context is still registered")
        assertTrue(held.count { it.config.isOverride } <= SharedServerContexts.MAX_OVERRIDES)
        val again = KslQuicCrypto.newSession(config) as KslQuicTlsSession
        try {
            assertTrue(again.context === baseContext, "and the next session shares it")
        } finally {
            again.close()
            id.close()
        }
    }

    // ---- the pause contract ----

    /** A server session driven to its SNI pause; the caller closes it. */
    private fun paused(config: TlsConfig): Pair<QuicTlsSession, DriveResult.WantSni> {
        val c = KslQuicCrypto.newSession(Fixtures.client())
        val s = KslQuicCrypto.newSession(config)
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        c.drive()
        while (true) {
            val ev = c.nextEvent() ?: break
            if (ev is TlsEvent.CryptoData) s.provide(ev.level, ev.data)
        }
        c.close()
        return s to assertIs<DriveResult.WantSni>(s.drive())
    }

    @Test fun drivingAPausedSessionKeepsItPaused() {
        val (s, w) = paused(server(selector = byName("server.test" to a)))
        try {
            assertIs<DriveResult.WantSni>(s.drive())
            assertNull(s.nextEvent(), "nothing for the client before the selection")
            s.resumeSni(runBlocking { s.selectSni(w.clientHello) })
            assertIs<DriveResult.WantRead>(s.drive(), "the server's flight is out, it waits for the client's Finished")
            assertTrue(s.nextEvent() != null, "the server's flight")
            assertEquals(leaf(a), s.localCertificates[0])
        } finally {
            s.close()
        }
    }

    @Test fun negative_resumeSniMisuse() {
        val config = server(selector = byName("server.test" to a))
        val (s, w) = paused(config)
        val (other, _) = paused(config)
        val plain = KslQuicCrypto.newSession(Fixtures.server())
        try {
            assertFailsWith<IllegalStateException>("no sniSelector") { runBlocking { plain.selectSni(w.clientHello) } }
        } finally {
            plain.close()
        }
        runBlocking { s.selectSni(w.clientHello) }.close() // the chosen identity's shared context, kept by its registry
        val before = liveContexts()
        try {
            val selection = runBlocking { s.selectSni(w.clientHello) }
            assertFailsWith<IllegalArgumentException>("another session's selection") { other.resumeSni(selection) }
            assertFailsWith<IllegalStateException>("closed by the refusal: the default must not stand in") { s.resumeSni(selection) }
            s.resumeSni(runBlocking { s.selectSni(w.clientHello) })
            val late = runBlocking { s.selectSni(w.clientHello) }
            assertFailsWith<IllegalStateException>("nothing pending any more") { s.resumeSni(late) }
        } finally {
            s.close()
            other.close()
        }
        assertTrue(liveContexts() <= before, "every selection's context was freed: $before -> ${liveContexts()}")
    }

    /** A connection that ends while its selector runs: the selection is closed or refused, and its context goes with it. */
    @Test fun negative_selectionsThatAreNeverAppliedLeakNoContext() {
        val config = server(selector = byName("server.test" to a))
        KslQuicCrypto.newSession(config).close() // the identity's shared base context, kept by its registry
        paused(config).let { (s, w) ->
            runBlocking { s.selectSni(w.clientHello) }.close() // and the chosen identity's, kept the same way
            s.close()
        }
        val before = liveContexts()
        repeat(20) {
            val (s, w) = paused(config)
            val selection = runBlocking { s.selectSni(w.clientHello) }
            if (it % 2 == 0) {
                selection.close()
                s.close()
            } else {
                s.close()
                assertFailsWith<IllegalStateException> { s.resumeSni(selection) }
            }
        }
        val after = liveContexts()
        assertTrue(after <= before, "contexts $before -> $after")
    }

    /** Random interleavings of selections, refusals and session ends never present an identity the selector did not choose. */
    @Test fun negative_randomSelectorAnswersNeverCrossIdentities() {
        val rnd = kotlin.random.Random(9001)
        val names = listOf("server.test", "proxy.internal", "unknown.test", "127.0.0.1")
        repeat(40) {
            val name = names[rnd.nextInt(names.size)]
            val chosen: TlsIdentity? =
                when (name) {
                    "server.test" -> if (rnd.nextBoolean()) a else null
                    "proxy.internal" -> b
                    else -> null
                }
            val p =
                handshake(
                    Fixtures.client(name = name),
                    server(default = a) { chosen?.let { id -> ServerTlsOverride(id) } },
                )
            try {
                when {
                    chosen != null -> {
                        assertTrue(p.ss.done, "$name -> chosen: ${p.ss.last}")
                        assertEquals(leaf(chosen), p.s.localCertificates[0])
                        assertEquals(leaf(chosen), p.c.peerCertificates[0])
                    }

                    name == "127.0.0.1" -> {
                        assertTrue(p.ss.done, "no SNI -> default: ${p.ss.last}")
                        assertEquals(leaf(a), p.s.localCertificates[0])
                    }

                    else -> {
                        assertEquals(112, assertIs<DriveResult.Failed>(p.ss.last).alert, name)
                    }
                }
            } finally {
                p.close()
            }
        }
    }
}
