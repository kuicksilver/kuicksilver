// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.KeyExchangeGroups.Companion.SECP256R1
import io.kuicksilver.tls.KeyExchangeGroups.Companion.SECP256R1MLKEM768
import io.kuicksilver.tls.KeyExchangeGroups.Companion.SECP384R1
import io.kuicksilver.tls.KeyExchangeGroups.Companion.SECP384R1MLKEM1024
import io.kuicksilver.tls.KeyExchangeGroups.Companion.SECP521R1
import io.kuicksilver.tls.KeyExchangeGroups.Companion.X25519
import io.kuicksilver.tls.KeyExchangeGroups.Companion.X25519MLKEM768
import io.kuicksilver.tls.KeyExchangeGroups.Companion.X448
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * `TlsConfig.Builder.keyExchangeGroups` (RFC 9846 sections 4.2.1, 4.3.7 and 4.3.8; RFC 9001 sections 4.7 and 4.8): the checks
 * at build time, and handshakes over QUIC and TCP whose lists meet on a non-first group (HelloRetryRequest) or not at all
 * (`handshake_failure`).
 */
class KeyExchangeGroupsTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private fun groups(
        vararg names: String,
        shares: Set<String>? = null,
    ) = KeyExchangeGroups(names.toList(), shares)

    @Test fun defaultIsTheListOfTheContextsAndTwoShares() {
        val d = KeyExchangeGroups.Default
        assertEquals(listOf(X25519MLKEM768, X25519, SECP256R1, X448, SECP384R1, SECP521R1), d.groups)
        assertEquals(listOf(X25519MLKEM768, X25519), d.keyShares)
        assertEquals("*X25519MLKEM768:*x25519:secp256r1:x448:secp384r1:secp521r1", d.kslList(TlsRole.Client))
        assertEquals("X25519MLKEM768:x25519:secp256r1:x448:secp384r1:secp521r1", d.kslList(TlsRole.Server))
        assertEquals(KeyExchangeGroups.Default, tlsConfig(TlsRole.Client) { serverName = "a.test" }.keyExchangeGroups)
    }

    /** Null key shares: the first group, and the first later one of the other kind (BoringSSL's default, ssl_setup_key_shares). */
    @Test fun derivedKeyShares() {
        assertEquals(listOf(SECP384R1), groups(SECP384R1, X25519).keyShares)
        assertEquals(listOf(SECP256R1MLKEM768, SECP256R1), groups(SECP256R1MLKEM768, SECP384R1MLKEM1024, SECP256R1).keyShares)
        assertEquals(listOf(X25519, X25519MLKEM768), groups(X25519, SECP256R1, X25519MLKEM768).keyShares)
        assertEquals(listOf(X25519MLKEM768), groups(X25519MLKEM768).keyShares)
        // given shares follow the order of the groups (RFC 9846 section 4.3.8: "MUST appear in the same order")
        assertEquals(listOf(SECP384R1, X25519), groups(SECP384R1, SECP256R1, X25519, shares = setOf(X25519, SECP384R1)).keyShares)
    }

    @Test fun namesInAnyCaseAreCanonical() {
        val g = groups("X25519", "SECP256R1", "x25519mlkem768", shares = setOf("X25519"))
        assertEquals(listOf(X25519, SECP256R1, X25519MLKEM768), g.groups)
        assertEquals(listOf(X25519), g.keyShares)
    }

    @Test fun negative_invalidGroupListsAreRefusedWhenBuilt() {
        val bad: List<Pair<String, () -> Any>> =
            listOf(
                "empty" to { KeyExchangeGroups(emptyList()) },
                "unknown" to { groups("P-256") },
                "finite field" to { groups("ffdhe2048") },
                "Brainpool" to { groups("brainpoolP256r1tls13") },
                "OpenSSL syntax" to { groups("*x25519") },
                "duplicate" to { groups(X25519, "X25519") },
                "no shares" to { groups(X25519, shares = emptySet()) },
                "share outside the list" to { groups(X25519, shares = setOf(SECP256R1)) },
                "five shares" to {
                    groups(
                        X25519MLKEM768,
                        SECP256R1MLKEM768,
                        SECP384R1MLKEM1024,
                        X25519,
                        X448,
                        shares = setOf(X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024, X25519, X448),
                    )
                },
            )
        for ((what, make) in bad) assertFailsWith<TlsException.Config>(what) { make() }
        val e = assertFailsWith<TlsException.Config> { groups("P-256") }
        assertTrue("secp256r1" in e.message.orEmpty(), "the message lists the supported names: ${e.message}")
    }

    @Test fun negative_buildRefusesGroupsTheRoleOrVersionsCannotUse() {
        assertFailsWith<TlsException.Config>("key shares on a server") {
            TcpFixtures.server { keyExchangeGroups = groups(X25519, SECP256R1, shares = setOf(X25519)) }
        }
        assertFailsWith<TlsException.Config>("TLS 1.2 without an elliptic curve") {
            TcpFixtures.client {
                versions = TlsVersions.Tls12And13
                keyExchangeGroups = groups(X25519MLKEM768)
            }
        }
        // the same lists where they are usable
        TcpFixtures.server { keyExchangeGroups = groups(X25519, SECP256R1) }
        TcpFixtures.client {
            versions = TlsVersions.Tls12And13
            keyExchangeGroups = groups(X25519MLKEM768, SECP384R1)
        }
    }

    @Test fun everyGroupIsAvailableInTheBundledOpenSsl() {
        val all = listOf(X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024, X25519, X448, SECP256R1, SECP384R1, SECP521R1)
        for (g in all) {
            val p = quic(Fixtures.client { keyExchangeGroups = groups(g) }, Fixtures.server { keyExchangeGroups = groups(g) })
            try {
                assertTrue(p.cs.done && p.ss.done, "$g: ${p.cs.last} / ${p.ss.last}")
                assertEquals(g, p.c.keyExchangeGroup)
                assertEquals(g, p.s.keyExchangeGroup)
            } finally {
                p.close()
            }
        }
    }

    /** The client's Initial CRYPTO flights: two when the server answered with a HelloRetryRequest. */
    private class Quic(
        val pump: Pump,
        val clientInitialFlights: Int,
    )

    private fun quic(
        client: TlsConfig,
        server: TlsConfig,
    ): Pump = quicCounted(client, server).pump

    private fun quicCounted(
        client: TlsConfig,
        server: TlsConfig,
    ): Quic {
        val c = KslQuicCrypto.newSession(client)
        val s = KslQuicCrypto.newSession(server)
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        var flights = 0
        val p = Pump(c, s)
        p.onEvent = { fromClient, ev ->
            if (fromClient && ev is TlsEvent.CryptoData && ev.level == EncryptionLevel.Initial) flights++
        }
        p.run()
        return Quic(p, flights)
    }

    /** RFC 9846 section 4.2.1: the server picks a group the client sent no share for and MUST answer with a HelloRetryRequest. */
    @Test fun quicListsMeetingOnANonFirstGroupCompleteAfterAHelloRetryRequest() {
        val q =
            quicCounted(
                Fixtures.client { keyExchangeGroups = groups(X25519, SECP256R1) },
                Fixtures.server { keyExchangeGroups = groups(SECP384R1, SECP256R1) },
            )
        try {
            assertTrue(q.pump.cs.done && q.pump.ss.done, "${q.pump.cs.last} / ${q.pump.ss.last}")
            assertEquals(2, q.clientInitialFlights, "a second ClientHello, at the Initial level (RFC 9001 section 4.7)")
            assertEquals(SECP256R1, q.pump.c.keyExchangeGroup)
            assertEquals(SECP256R1, q.pump.s.keyExchangeGroup)
        } finally {
            q.pump.close()
        }
    }

    /** The server's own order decides among the client's shares, and no HelloRetryRequest is spent on a preferred group. */
    @Test fun quicServerPicksByItsOwnOrder() {
        val q =
            quicCounted(
                Fixtures.client { keyExchangeGroups = groups(X25519, SECP256R1, shares = setOf(X25519, SECP256R1)) },
                Fixtures.server { keyExchangeGroups = groups(SECP256R1, X25519) },
            )
        try {
            assertTrue(q.pump.cs.done && q.pump.ss.done)
            assertEquals(1, q.clientInitialFlights)
            assertEquals(SECP256R1, q.pump.s.keyExchangeGroup)
        } finally {
            q.pump.close()
        }
    }

    /** RFC 9846 section 4.2.1: no group in common is `handshake_failure`; the server's session fails with alert 40. */
    @Test fun negative_quicListsWithoutACommonGroupFailWithHandshakeFailure() {
        val p =
            quic(
                Fixtures.client { keyExchangeGroups = groups(X25519, X448) },
                Fixtures.server { keyExchangeGroups = groups(SECP384R1, SECP256R1) },
            )
        try {
            val f = assertIs<DriveResult.Failed>(p.ss.last)
            assertEquals(40, f.alert)
            assertNull(p.c.keyExchangeGroup)
        } finally {
            p.close()
        }
    }

    /** An sniSelector answer's groups decide once it applies, in both directions. */
    @Test fun quicSniOverrideBringsItsOwnGroups() {
        val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        for ((base, override) in listOf(groups(SECP384R1) to groups(X25519), groups(X25519) to groups(SECP384R1))) {
            val server =
                Fixtures.server {
                    keyExchangeGroups = base
                    sniSelector = { ServerTlsOverride(identity, null, null, null, null, override) }
                }
            val q = quicCounted(Fixtures.client { keyExchangeGroups = groups(X25519, SECP384R1) }, server)
            try {
                assertTrue(q.pump.cs.done && q.pump.ss.done, "override $override: ${q.pump.ss.last}")
                assertEquals(override.groups[0], q.pump.s.keyExchangeGroup)
                assertEquals(if (override.groups[0] == X25519) 1 else 2, q.clientInitialFlights)
            } finally {
                q.pump.close()
            }
        }
    }

    @Test fun negative_anOverrideWithKeySharesEndsTheHandshake() {
        val identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
        val server =
            Fixtures.server {
                sniSelector = { ServerTlsOverride(identity, null, null, null, null, groups(X25519, shares = setOf(X25519))) }
            }
        val p = quic(Fixtures.client(), server)
        try {
            assertIs<DriveResult.Failed>(p.ss.last)
            assertTrue(!p.cs.done)
        } finally {
            p.close()
        }
    }

    @Test fun tcpListsMeetingOnANonFirstGroupComplete(): Unit =
        runBlocking {
            val (cd, sd) =
                connect(
                    TcpFixtures.client { keyExchangeGroups = groups(X25519, SECP256R1) },
                    TcpFixtures.server { keyExchangeGroups = groups(SECP384R1, SECP256R1) },
                )
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals(SECP256R1, c.keyExchangeGroup)
                assertEquals(SECP256R1, s.keyExchangeGroup)
            } finally {
                c.close()
                s.close()
            }
        }

    /** Over TCP the alert reaches the client: `TlsException.AlertReceived` 40 (`handshake_failure`). */
    @Test fun negative_tcpListsWithoutACommonGroupFailWithHandshakeFailure() {
        val (cd, sd) =
            connect(
                TcpFixtures.client { keyExchangeGroups = groups(X25519, X448) },
                TcpFixtures.server { keyExchangeGroups = groups(SECP384R1, SECP256R1) },
            )
        runBlocking {
            val e = assertFailsWith<TlsException.AlertReceived> { withTimeout(10.seconds) { cd.await() } }
            assertEquals(40, e.code)
            assertFailsWith<TlsException> { withTimeout(10.seconds) { sd.await() } }
        }
    }

    /** Tls12And13 on both sides: TLS 1.3, the server's first of the client's shares (TLS 1.2 itself: C `groups_tls12_curves`). */
    @Test fun tcpTls12And13KeepsTheServerOrderAmongShares(): Unit =
        runBlocking {
            val (cd, sd) =
                connect(
                    TcpFixtures.client {
                        versions = TlsVersions.Tls12And13
                        keyExchangeGroups = groups(X25519MLKEM768, X25519, SECP384R1)
                    },
                    TcpFixtures.server {
                        versions = TlsVersions.Tls12And13
                        keyExchangeGroups = groups(SECP384R1, X25519)
                    },
                )
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals(TlsVersion.Tls13, c.protocolVersion)
                assertEquals(X25519, c.keyExchangeGroup, "TLS 1.3: the server's first of the client's shares (x25519)")
            } finally {
                c.close()
                s.close()
            }
        }
}
