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
        zeroRtt: Boolean = true,
    ): Outcome {
        val c = KslQuicCrypto.newSession(client, earlyData = true)
        val s = KslQuicCrypto.newSession(server, earlyData = true)
        val admission = Admission()
        assertTrue(s.enableEarlyData(byteArrayOf(7), admission))
        if (ticket != null) {
            assertTrue(c.resume(ticket), "the client offers the ticket")
            if (zeroRtt) assertTrue(c.enableEarlyData(null, null), "the ticket allows 0-RTT")
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
     * RFC 6066 section 3: a server "MUST NOT accept the request to resume the session if the server_name extension contains a
     * different name". The selector serves both names with the same certificate, so only the name tells the sessions apart.
     */
    @Test fun negative_ticketIsNotResumedUnderAnotherName() {
        val selector = byName("server.test" to a, "proxy.internal" to a)
        val ticket = firstTicket(Fixtures.client(), server(selector = selector))
        // SNI proxy.internal, the certificate still checked as server.test's: a client that offers server.test's ticket there
        // (without 0-RTT: OpenSSL's client refuses early data under another SNI, "inconsistent early data sni")
        val client = Fixtures.client(name = "proxy.internal", trust = TrustConfig.ExpectedName("server.test", testCaTrust))
        val o = earlyHandshake(client, server(selector = selector), ticket, zeroRtt = false)
        try {
            assertTrue(o.pump.cs.done && o.pump.ss.done, "${(o.pump.cs.last as? DriveResult.Failed)?.exception} / ${o.pump.ss.last}")
            assertEquals("proxy.internal", o.pump.s.sniSelectedFor)
            assertFalse((o.pump.s as KslQuicTlsSession).sessionReusedForTest, "not resumed under another name")
        } finally {
            o.close()
        }
        // control: the same ticket path under the name it was issued for resumes
        val again = firstTicket(Fixtures.client(), server(selector = selector))
        val r = earlyHandshake(Fixtures.client(), server(selector = selector), again)
        try {
            assertTrue((r.pump.s as KslQuicTlsSession).sessionReusedForTest)
        } finally {
            r.close()
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
