// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.io.encoding.Base64
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Encrypted Client Hello (RFC 9849) through `TlsConfig`: the client's configuration list, GREASE and the rejection with
 * retry configurations, the server's keys and their rotation, over QUIC ([KslQuicCrypto]) and TCP ([TlsConnection]). The
 * keys are [EchTestKeys] (public_name `ech.wild.test`, which the test server certificate covers through `*.wild.test`); the
 * inner name is `server.test`.
 */
class EchTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    private val keyA = EchKey(EchTestKeys.A)
    private val keyB = EchKey(EchTestKeys.B)

    /** The ECHConfigList of a key: the base64 body of its ECHCONFIG block, as published in the HTTPS record. */
    private fun listOf(pem: String): EchConfigList {
        val body = pem.substringAfter("-----BEGIN ECHCONFIG-----").substringBefore("-----END ECHCONFIG-----")
        return EchConfigList.parseBase64(body.lines().joinToString(""))
    }

    private val listA by lazy { listOf(EchTestKeys.A) }
    private val listB by lazy { listOf(EchTestKeys.B) }

    private fun quic(
        client: TlsConfig,
        server: TlsConfig,
        onVerify: ((DriveResult.WantVerify) -> VerifyResult)? = null,
    ): Pump {
        val c = KslQuicCrypto.newSession(client)
        val s = KslQuicCrypto.newSession(server)
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        val p = Pump(c, s)
        p.run(onVerify = onVerify)
        return p
    }

    @Test fun listParsingKeepsUsableConfigs() {
        assertTrue(listA.isUsable)
        assertEquals(listA, EchConfigList.parse(listA.bytes))
        // another version (0xfe0c) before it is ignored, the list stays usable (RFC 9849 section 4)
        val other = byteArrayOf(0xfe.toByte(), 0x0c, 0, 3, 1, 2, 3)
        val inner = listA.bytes.copyOfRange(2, listA.bytes.size)
        val total = other.size + inner.size
        val both = byteArrayOf((total ushr 8).toByte(), total.toByte()) + other + inner
        assertTrue(EchConfigList.parse(both).isUsable)
        val onlyOther = byteArrayOf(0, other.size.toByte()) + other
        assertFalse(EchConfigList.parse(onlyOther).isUsable)
    }

    @Test fun negative_malformedListsAreRefused() {
        assertFailsWith<TlsException.Config> { EchConfigList.parse(byteArrayOf(0, 5, 1)) }
        assertFailsWith<TlsException.Config> { EchConfigList.parse(ByteArray(0)) }
        assertFailsWith<TlsException.Config> { EchConfigList.parseBase64("not base64 !") }
        val truncated = listA.bytes.copyOf(listA.bytes.size - 1)
        assertFailsWith<TlsException.Config> { EchConfigList.parse(truncated) }
    }

    @Test fun negative_configurationsInTheWrongPlaceAreRefused() {
        assertFailsWith<TlsException.Config> { Fixtures.server { echConfigList = listA } }
        assertFailsWith<TlsException.Config> { Fixtures.client { echKeys = EchServerKeys(listOf(keyA)) } }
        // ECH is TLS 1.3 only (RFC 9849 section 6.1; ADR-0019: the TLS 1.2 support of ksl and ECH do not mix on OpenSSL 4.1)
        assertFailsWith<TlsException.Config> {
            TcpFixtures.client {
                versions = TlsVersions.Tls12And13
                echConfigList = listA
            }
        }
        assertFailsWith<TlsException.Config> { EchServerKeys(listOf(EchKey(EchTestKeys.A, inRetryConfigs = false))) }
        assertFailsWith<TlsException.Config> { EchServerKeys(emptyList()) }
        assertFailsWith<TlsException.Config> {
            EchServerKeys(
                listOf(EchKey("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")),
            )
        }
    }

    @Test fun quicAccepted() {
        val p = quic(Fixtures.client { echConfigList = listA }, Fixtures.server { echKeys = EchServerKeys(listOf(keyA)) })
        try {
            assertTrue(p.cs.done && p.ss.done, "${p.cs.last} / ${p.ss.last}")
            assertEquals(EchStatus.Accepted, p.c.echStatus)
            assertEquals(EchStatus.Accepted, p.s.echStatus)
        } finally {
            p.close()
        }
    }

    /** RFC 9849 section 6.1.6: rejected, the handshake fails with ech_required and the server's retry configurations. */
    @Test fun negative_quicRejectedReportsRetryConfigs() {
        val server = Fixtures.server { echKeys = EchServerKeys(listOf(keyB)) }
        val p = quic(Fixtures.client { echConfigList = listA }, server)
        try {
            val f = assertIs<DriveResult.Failed>(p.cs.last)
            val e = assertIs<TlsException.EchRejected>(f.exception)
            assertEquals(121, f.alert)
            assertEquals(listB, e.retryConfigs)
            assertEquals(EchStatus.Rejected, p.c.echStatus)
        } finally {
            p.close()
        }
        // the single retry with them is accepted
        val r = quic(Fixtures.client { echConfigList = p.retryOf() }, server)
        try {
            assertTrue(r.cs.done && r.ss.done)
            assertEquals(EchStatus.Accepted, r.c.echStatus)
        } finally {
            r.close()
        }
    }

    private fun Pump.retryOf(): EchConfigList =
        assertNotNull((assertIs<DriveResult.Failed>(cs.last).exception as TlsException.EchRejected).retryConfigs)

    /** The paused path (a platform or custom verifier) checks the public_name after a rejection (RFC 9849 section 6.1.7). */
    @Test fun quicPausedVerifierSeesThePublicNameOnRejection() {
        val seen = ArrayList<String?>()
        val client =
            Fixtures.client(
                trust =
                    TrustConfig.Custom { chain, host, _ ->
                        seen += host
                        if (host == "ech.wild.test") {
                            VerifyResult.Accepted(chain)
                        } else {
                            VerifyResult.Rejected(VerifyReason.HostnameMismatch(host ?: "", emptyList()))
                        }
                    },
            ) { echConfigList = listA }
        val c = KslQuicCrypto.newSession(client)
        val s = KslQuicCrypto.newSession(Fixtures.server { echKeys = EchServerKeys(listOf(keyB)) })
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        val p = Pump(c, s)
        p.run(onVerify = { runBlocking { c.verifyPeer(it.chain) } })
        try {
            assertEquals(listOf<String?>("ech.wild.test"), seen, "the verifier was asked for the public_name")
            assertIs<TlsException.EchRejected>(assertIs<DriveResult.Failed>(p.cs.last).exception)
        } finally {
            p.close()
        }
    }

    /** A client whose rejection goes through the paused path with [trust]: the pump after a server with key B. */
    private fun rejectedThrough(trust: TrustConfig): Pump {
        val c = KslQuicCrypto.newSession(Fixtures.client(trust = trust) { echConfigList = listA })
        val s = KslQuicCrypto.newSession(Fixtures.server { echKeys = EchServerKeys(listOf(keyB)) })
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        val p = Pump(c, s)
        p.run(onVerify = { runBlocking { c.verifyPeer(it.chain) } })
        return p
    }

    /**
     * Pins are the origin's (RFC 7469 section 2.6: a pinned host's own keys): during a rejection the certificate is the
     * public_name's, authenticated by the base trust for that name (RFC 9849 section 6.1.7), and the origin's pins do not
     * apply to it; the connection is never used for data, and the retry checks the pins against the origin's certificate.
     * The paused path (a platform verifier under the pins) through [Verification].
     */
    @Test fun pinsDoNotApplyToThePublicNameCertificate(): Unit =
        runBlocking {
            val chain = listOf(Certificate(TestCerts.server))
            val config = Fixtures.client(trust = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32) { 7 }))))
            val v = Verification(config, platform = { c, _, _ -> PlatformVerdict(VerifyResult.Accepted(c), c) })
            assertIs<VerifyResult.Accepted>(v.verify(chain, HostName.normalize(EchTestKeys.PUBLIC_NAME), echPublicName = true))
            // the origin's own certificate is held to them as always
            assertIs<VerifyResult.Rejected>(v.verify(chain, HostName.normalize("server.test")))
        }

    /** The OpenSSL path under pins: a rejection authenticated by the CA for the public_name reports the retry configurations. */
    @Test fun pinsDoNotFailAnAnchoredRejection() {
        val trust = TrustConfig.Pinned(setOf(SpkiSha256(ByteArray(32) { 7 })), base = TrustConfig.AnchoredCa(listOf(Fixtures.testCa)))
        val p = quic(Fixtures.client(trust = trust) { echConfigList = listA }, Fixtures.server { echKeys = EchServerKeys(listOf(keyB)) })
        try {
            assertEquals(listB, assertIs<TlsException.EchRejected>(assertIs<DriveResult.Failed>(p.cs.last).exception).retryConfigs)
        } finally {
            p.close()
        }
    }

    /** The base trust still decides for the public_name under pins: a platform verifier that refuses it fails the rejection. */
    @Test fun negative_pinnedRejectionStillNeedsTheBaseTrust(): Unit =
        runBlocking {
            val chain = listOf(Certificate(TestCerts.server))
            val config = Fixtures.client(trust = TrustConfig.Pinned(setOf(chain[0].spkiSha256)))
            val v =
                Verification(config, platform = { _, h, _ ->
                    PlatformVerdict(VerifyResult.Rejected(VerifyReason.HostnameMismatch(h.value, emptyList())), null)
                })
            assertIs<VerifyResult.Rejected>(v.verify(chain, HostName.normalize(EchTestKeys.PUBLIC_NAME), echPublicName = true))
        }

    /**
     * Trust on first use cannot authenticate a public_name it has no pin for: a rejection is no first contact (RFC 9849
     * section 6.1.7: the certificate MUST be valid for the public_name; such connections are only used to trigger retries),
     * so nothing is stored and the rejection fails; with a pin stored for the public_name it is checked against it.
     */
    @Test fun negative_tofuDoesNotTrustAPublicNameOnFirstContact() {
        val store = MemoryTofu()
        val p = rejectedThrough(TrustConfig.Tofu(store))
        try {
            assertIs<TlsException.Verify>(assertIs<DriveResult.Failed>(p.cs.last).exception)
            assertTrue(store.map.isEmpty(), "nothing stored for ${store.map.keys}")
        } finally {
            p.close()
        }
        // a pin of the public_name taken on a direct contact authenticates the rejection
        val leaf = Certificate(TestCerts.server)
        runBlocking { store.put(EchTestKeys.PUBLIC_NAME, leaf.spkiSha256) }
        val known = rejectedThrough(TrustConfig.Tofu(store))
        try {
            assertIs<TlsException.EchRejected>(assertIs<DriveResult.Failed>(known.cs.last).exception)
        } finally {
            known.close()
        }
    }

    private class MemoryTofu : TofuStore {
        val map = HashMap<String, SpkiSha256>()

        override suspend fun get(name: String): SpkiSha256? = map[name]

        override suspend fun put(
            name: String,
            pin: SpkiSha256,
        ) {
            map[name] = pin
        }
    }

    /** A certificate that does not cover the public_name: the rejection is not authenticated, nothing to retry with. */
    @Test fun negative_quicUnauthenticatedRejectionHasNoRetryConfigs() {
        val p =
            quic(
                Fixtures.client { echConfigList = listA },
                Fixtures.server(listOf(TestCerts.serverOtherKey), TestCerts.serverOtherKeyKey) { echKeys = EchServerKeys(listOf(keyB)) },
            )
        try {
            val f = assertIs<DriveResult.Failed>(p.cs.last)
            assertIs<TlsException.Verify>(f.exception)
            assertEquals(EchStatus.Offered, p.c.echStatus)
        } finally {
            p.close()
        }
    }

    @Test fun negative_quicServerWithoutEchIsSecurelyDisabled() {
        val p = quic(Fixtures.client { echConfigList = listA }, Fixtures.server())
        try {
            val e = assertIs<TlsException.EchRejected>(assertIs<DriveResult.Failed>(p.cs.last).exception)
            assertNull(e.retryConfigs)
        } finally {
            p.close()
        }
    }

    @Test fun quicGreaseByDefault() {
        val p = quic(Fixtures.client(), Fixtures.server { echKeys = EchServerKeys(listOf(keyA)) })
        try {
            assertTrue(p.cs.done && p.ss.done)
            assertEquals(EchStatus.Grease, p.c.echStatus)
            assertEquals(EchStatus.Rejected, p.s.echStatus, "the server saw an extension it could not decrypt")
        } finally {
            p.close()
        }
        val off = quic(Fixtures.client { echGrease = false }, Fixtures.server())
        try {
            assertTrue(off.cs.done)
            assertEquals(EchStatus.None, off.c.echStatus)
        } finally {
            off.close()
        }
    }

    /** A rotation reaches the contexts already built from the configuration; the old key keeps decrypting while it is kept. */
    @Test fun rotation() {
        val keys = EchServerKeys(listOf(keyA))
        val server = Fixtures.server { echKeys = keys }
        val first = quic(Fixtures.client { echConfigList = listA }, server)
        first.close()
        assertEquals(EchStatus.Accepted, first.c.echStatus)
        keys.rotate(listOf(keyB, EchKey(EchTestKeys.A, inRetryConfigs = false)))
        val old = quic(Fixtures.client { echConfigList = listA }, server)
        old.close()
        assertEquals(EchStatus.Accepted, old.c.echStatus, "the old key decrypts while kept")
        keys.rotate(listOf(keyB))
        val gone = quic(Fixtures.client { echConfigList = listA }, server)
        gone.close()
        assertEquals(listB, (assertIs<DriveResult.Failed>(gone.cs.last).exception as TlsException.EchRejected).retryConfigs)
    }

    @Test fun tcpAcceptedAndRejected(): Unit =
        runBlocking {
            val (cd, sd) =
                connect(
                    TcpFixtures.client { echConfigList = listA },
                    TcpFixtures.server { echKeys = EchServerKeys(listOf(keyA)) },
                )
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals(EchStatus.Accepted, c.echStatus)
                assertEquals(EchStatus.Accepted, s.echStatus)
            } finally {
                c.close()
                s.close()
            }
            val (rd, rs) =
                connect(
                    TcpFixtures.client { echConfigList = listA },
                    TcpFixtures.server { echKeys = EchServerKeys(listOf(keyB)) },
                )
            val e = assertFailsWith<TlsException.EchRejected> { withTimeout(10.seconds) { rd.await() } }
            assertContentEquals(listB.bytes, e.retryConfigs?.bytes)
            assertFailsWith<TlsException> { withTimeout(10.seconds) { rs.await() } }
        }

    @Test fun base64OfTheRecordParses() {
        assertEquals(listA, EchConfigList.parseBase64(Base64.encode(listA.bytes)))
    }
}
