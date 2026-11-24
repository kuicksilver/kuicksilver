// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Certificate revocation (RFC 9325 section 7.5): a server staples an OCSP response ([OcspStapling]), a client checks it
 * ([RevocationPolicy]), and CRLs join an [TrustConfig.AnchoredCa], over QUIC and TCP. The PKI, the responses and the CRLs
 * come from `tools/certs/gen-revocation-certs.sh`.
 */
class RevocationTest {
    /** Session caches of this test's own handshakes, closed after it (their native sessions). */
    private val caches = TestCaches()

    @AfterTest fun closeCaches() = caches.close()

    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val root = Certificate(RevocationCerts.rvRoot)
    private val anchored = TrustConfig.AnchoredCa(listOf(root))

    private fun client(
        policy: RevocationPolicy = RevocationPolicy.StapledIfPresent,
        trust: TrustConfig = anchored,
    ) = Fixtures.client(trust) { revocation = policy }

    private fun server(
        leaf: ByteArray = RevocationCerts.rvLeaf,
        key: ByteArray = RevocationCerts.rvLeafKey,
        stapling: OcspStapling? = null,
    ) = Fixtures.server(listOf(leaf, RevocationCerts.rvMid), key) { ocspStapling = stapling }

    private fun quic(
        client: TlsConfig,
        server: TlsConfig,
    ): Pump {
        val p =
            Pump(KslQuicCrypto.newSession(client), KslQuicCrypto.newSession(server)).also {
                it.c.setTransportParameters(Fixtures.tp)
                it.s.setTransportParameters(Fixtures.tp)
            }
        p.run()
        return p
    }

    private fun quicPasses(
        client: TlsConfig,
        server: TlsConfig,
    ) {
        val p = quic(client, server)
        try {
            assertTrue(p.cs.done && p.ss.done, "the handshake completes: ${p.cs.last}")
        } finally {
            p.close()
        }
    }

    private fun quicRefused(
        client: TlsConfig,
        server: TlsConfig,
        alert: Int = 113,
    ): VerifyReason {
        val p = quic(client, server)
        try {
            val f = assertIs<DriveResult.Failed>(p.cs.last, "the client refuses")
            assertEquals(alert, f.alert)
            return assertIs<TlsException.Verify>(f.exception).reason
        } finally {
            p.close()
        }
    }

    private val good = OcspStapling(RevocationCerts.ocspGood)

    @Test fun quicStapledGoodPasses() {
        quicPasses(client(), server(stapling = good))
        quicPasses(client(RevocationPolicy.RequireStapled), server(stapling = OcspStapling(RevocationCerts.ocspGoodDelegated)))
    }

    @Test fun negative_quicStapledRevokedFails() {
        val r =
            quicRefused(
                client(),
                server(RevocationCerts.rvLeafRevoked, RevocationCerts.rvLeafRevokedKey, OcspStapling(RevocationCerts.ocspRevoked)),
            )
        assertEquals(VerifyReason.Revoked, r)
    }

    @Test fun quicNoStapleSoftFails() {
        quicPasses(client(), server())
        quicPasses(client(RevocationPolicy.Off), server())
    }

    @Test fun negative_quicRequiredStapleMissing() {
        assertEquals(VerifyReason.UnknownRevocationStatus, quicRefused(client(RevocationPolicy.RequireStapled), server()))
    }

    @Test fun negative_quicMustStapleLeafWithoutStaple() {
        val s = server(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey)
        assertEquals(VerifyReason.UnknownRevocationStatus, quicRefused(client(), s), "RFC 7633: hard-fail by default")
        quicPasses(
            client(),
            server(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey, OcspStapling(RevocationCerts.ocspMustStaple)),
        )
    }

    @Test fun negative_quicUnknownRequired() {
        val s = server(RevocationCerts.rvLeafUnlisted, RevocationCerts.rvLeafUnlistedKey, OcspStapling(RevocationCerts.ocspUnknown))
        quicPasses(client(), s)
        assertEquals(VerifyReason.UnknownRevocationStatus, quicRefused(client(RevocationPolicy.RequireStapled), s))
    }

    /** The server checks before it staples: a stale response, or one for another certificate, is not sent. */
    @Test fun negative_serverStaplesNoStaleOrForeignResponse() {
        assertEquals(
            VerifyReason.UnknownRevocationStatus,
            quicRefused(client(RevocationPolicy.RequireStapled), server(stapling = OcspStapling(RevocationCerts.ocspStale))),
        )
        assertEquals(
            VerifyReason.UnknownRevocationStatus,
            quicRefused(client(RevocationPolicy.RequireStapled), server(stapling = OcspStapling(RevocationCerts.ocspRevoked))),
        )
    }

    /**
     * RFC 8446 section 4.4.2: in TLS 1.3 the response travels in the leaf's CertificateEntry, whose extensions are
     * `Extension extensions<0..2^16-1>`: with its 4-byte extension header and the CertificateStatus' status_type and 3-byte
     * length, a response of more than 65527 bytes cannot be sent. RFC 6066 section 8 lets a server send none, so such a
     * response is not stapled and the handshake goes on (it used to fail in the server). [padded] pads ocspGood with copies
     * of its certificate in BasicOCSPResponse's unsigned certs field: still valid and fresh, only larger.
     */
    @Test fun oversizeResponseIsNotStapledInTls13() {
        val big = padded(RevocationCerts.ocspGood, 70_000)
        assertTrue(big.size > OcspStapling.MAX_TLS13_RESPONSE, "${big.size}")
        quicPasses(client(), server(stapling = OcspStapling(big)))
        assertEquals(
            VerifyReason.UnknownRevocationStatus,
            quicRefused(client(RevocationPolicy.RequireStapled), server(stapling = OcspStapling(big))),
        )
        val fits = padded(RevocationCerts.ocspGood, 60_000)
        assertTrue(fits.size <= OcspStapling.MAX_TLS13_RESPONSE, "${fits.size}")
        quicPasses(client(RevocationPolicy.RequireStapled), server(stapling = OcspStapling(fits)))
    }

    @Test fun oversizeResponseIsNotStapledOverTcpTls13(): Unit =
        runBlocking {
            val (c, s) = tcp(tcpClient(), tcpServer(stapling = OcspStapling(padded(RevocationCerts.ocspGood, 70_000))))
            c.close()
            s.close()
        }

    /**
     * [response] (one certificate in BasicOCSPResponse's certs) grown to exactly [size] bytes with valid certificates of the
     * revocation PKI added to that unsigned field: the signature and the RFC 6960 checks are unchanged.
     */
    private fun padded(
        response: ByteArray,
        size: Int,
    ): ByteArray {
        fun lenOf(n: Int) =
            when {
                n < 0x80 -> 1
                n < 0x100 -> 2
                n < 0x10000 -> 3
                else -> 4
            }

        fun len(n: Int): ByteArray =
            when (lenOf(n)) {
                1 -> byteArrayOf(n.toByte())
                2 -> byteArrayOf(0x81.toByte(), n.toByte())
                3 -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
                else -> byteArrayOf(0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
            }

        fun tlv(
            tag: Int,
            content: ByteArray,
        ) = byteArrayOf(tag.toByte()) + len(content.size) + content

        // the children of the constructed TLV at [at]: (tag, whole TLV)
        fun children(
            b: ByteArray,
            at: Int,
        ): List<Pair<Int, ByteArray>> {
            fun header(i: Int): Pair<Int, Int> { // (header length, content length)
                val l = b[i + 1].toInt() and 0xff
                if (l < 0x80) return 2 to l
                var n = 0
                for (k in 0 until (l and 0x7f)) n = (n shl 8) or (b[i + 2 + k].toInt() and 0xff)
                return 2 + (l and 0x7f) to n
            }
            val (h, n) = header(at)
            val out = ArrayList<Pair<Int, ByteArray>>()
            var i = at + h
            while (i < at + h + n) {
                val (ch, cn) = header(i)
                out += (b[i].toInt() and 0xff) to b.copyOfRange(i, i + ch + cn)
                i += ch + cn
            }
            return out
        }
        val top = children(response, 0) // responseStatus, [0] responseBytes
        val rb = children(top[1].second, 0).single().second // SEQUENCE { responseType, response }
        val (oid, octets) = children(rb, 0).let { it[0].second to it[1].second }
        val first = octets[1].toInt() and 0xff
        val basicDer = octets.copyOfRange(2 + (if (first < 0x80) 0 else first and 0x7f), octets.size) // the OCTET STRING's content
        val basic = children(basicDer, 0) // tbsResponseData, signatureAlgorithm, signature, [0] certs
        val head = basic[0].second + basic[1].second + basic[2].second
        val cert = children(children(basic[3].second, 0).single().second, 0).first().second

        // the size of the whole response when the certs field's SEQUENCE holds [certBytes] bytes of certificates
        fun total(certBytes: Int): Int {
            fun wrap(n: Int) = 1 + lenOf(n) + n
            val basicLen = wrap(head.size + wrap(wrap(certBytes)))
            val rbLen = wrap(oid.size + wrap(basicLen))
            return wrap(top[0].second.size + wrap(rbLen))
        }
        val bytes = (head.size until size).firstOrNull { total(it) == size } ?: error("no encoding of $size bytes")
        // the extra certificates: copies of the largest, then two others in counts that make up the rest exactly
        val pool =
            listOf(
                RevocationCerts.rvMid,
                RevocationCerts.rvRoot,
                RevocationCerts.rvLeaf,
                RevocationCerts.rvClient,
                RevocationCerts.rvLeafMustStaple,
                RevocationCerts.rvResponder,
                RevocationCerts.rvResponderWeak,
            ).distinctBy { it.size }
                .sortedByDescending { it.size }
        val rest = bytes - cert.size
        for (x in pool.drop(1)) {
            for (y in pool.drop(1)) {
                if (x === y) continue
                for (b in 0..pool[0].size) {
                    for (c in 0..pool[0].size) {
                        val r = rest - b * x.size - c * y.size
                        if (r < 0) break
                        if (r % pool[0].size != 0) continue
                        val extra = List(r / pool[0].size) { pool[0] } + List(b) { x } + List(c) { y }
                        val certs = (listOf(cert) + extra).reduce { u, v -> u + v }
                        val newBasic = tlv(0x30, head + tlv(0xa0, tlv(0x30, certs)))
                        return tlv(0x30, top[0].second + tlv(0xa0, tlv(0x30, oid + tlv(0x04, newBasic)))).also { check(it.size == size) }
                    }
                }
            }
        }
        error("no certificates add up to $size bytes")
    }

    /** The boundary itself: 65527 bytes are stapled over TLS 1.3 (QUIC and TCP), 65528 are not. */
    @Test fun tls13StaplesUpTo65527Bytes(): Unit =
        runBlocking {
            val atLimit = padded(RevocationCerts.ocspGood, OcspStapling.MAX_TLS13_RESPONSE)
            val over = padded(RevocationCerts.ocspGood, OcspStapling.MAX_TLS13_RESPONSE + 1)
            assertEquals(65_527, atLimit.size)
            quicPasses(client(RevocationPolicy.RequireStapled), server(stapling = OcspStapling(atLimit)))
            assertEquals(
                VerifyReason.UnknownRevocationStatus,
                quicRefused(client(RevocationPolicy.RequireStapled), server(stapling = OcspStapling(over))),
            )
            assertEquals(null, requiredStapleOutcome(tcpServer(stapling = OcspStapling(atLimit))))
            assertEquals(VerifyReason.UnknownRevocationStatus, requiredStapleOutcome(tcpServer(stapling = OcspStapling(over))))
        }

    /** RFC 6066 section 8 inside a TLS 1.2 CertificateStatus message: a response of 2^24-5 bytes is taken, 2^24-4 refused. */
    @Test fun negative_responseLimitIsTheCertificateStatusMessage() {
        fun der(n: Int) = ByteArray(n).also { it[0] = 0x30 }
        assertEquals((1 shl 24) - 5, OcspStapling(der((1 shl 24) - 5)).current?.size)
        assertFailsWith<TlsException.Config> { OcspStapling(der((1 shl 24) - 4)) }
    }

    @Test fun updateReplacesTheStapledResponse() {
        val st = OcspStapling()
        val s = server(stapling = st)
        assertEquals(VerifyReason.UnknownRevocationStatus, quicRefused(client(RevocationPolicy.RequireStapled), s))
        st.update(RevocationCerts.ocspGood)
        quicPasses(client(RevocationPolicy.RequireStapled), s)
        val chain = listOf(Certificate(RevocationCerts.rvLeaf), Certificate(RevocationCerts.rvMid))
        assertTrue(st.isUsableFor(chain))
        st.update(RevocationCerts.ocspStale)
        assertFalse(st.isUsableFor(chain), "a stale response is reported unusable")
    }

    @Test fun negative_staplingArgumentsRefused() {
        assertFailsWith<TlsException.Config> { OcspStapling(ByteArray(0)) }
        assertFailsWith<TlsException.Config> { OcspStapling().update(byteArrayOf(1, 2, 3)) }
        assertFailsWith<TlsException.Config> { Fixtures.client { ocspStapling = good } }
    }

    /**
     * The trusts whose chain `ksl` does not verify itself (the pause path): an application's verifier, TOFU, and the
     * platform's where it is not OpenSSL (the JVM, Android, Apple, Windows), each under pins too. The pump's verifier
     * accepts the chain, standing in for what each would decide.
     */
    private val pausedTrusts: List<TrustConfig>
        get() {
            val custom = TrustConfig.Custom(CertificateVerifier { chain, _, _ -> VerifyResult.Accepted(chain) })
            val store =
                object : TofuStore {
                    override suspend fun get(name: String): SpkiSha256? = null

                    override suspend fun put(
                        name: String,
                        pin: SpkiSha256,
                    ) {}
                }
            val pin = Certificate(RevocationCerts.rvLeafMustStaple).spkiSha256
            return listOfNotNull(
                custom,
                TrustConfig.Tofu(store),
                TrustConfig.ExpectedName("server.test", base = custom),
                TrustConfig.Platform.takeIf { !platformTrustViaOpenSsl },
                TrustConfig.Pinned(setOf(pin), base = TrustConfig.Platform).takeIf { !platformTrustViaOpenSsl },
            )
        }

    private fun pausedQuic(
        client: TlsConfig,
        server: TlsConfig,
    ): Pump {
        val p =
            Pump(KslQuicCrypto.newSession(client), KslQuicCrypto.newSession(server)).also {
                it.c.setTransportParameters(Fixtures.tp)
                it.s.setTransportParameters(Fixtures.tp)
            }
        p.run(onVerify = { VerifyResult.Accepted(it.chain) })
        return p
    }

    private val mustStaple get() = server(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey)

    /**
     * RFC 7633 section 4.3.3: a client "MUST treat a certificate with a TLS feature extension as an invalid certificate if
     * the features offered by the server do not contain all features present in both the client's ClientHello message and
     * the TLS feature extension"; section 4.2.3.1: such a configuration it "SHOULD reject". The client sends status_request
     * under every [RevocationPolicy] but `Off` on every trust path, so a must-staple leaf without a staple fails everywhere,
     * the platform's and an application's verifier included (`UnknownRevocationStatus`, alert 113). Before 0.3.0 only the
     * paths `ksl` verifies (AnchoredCa, Platform on Linux) held it.
     */
    @Test fun negative_mustStapleEnforcedOnEveryTrustPath() {
        for (trust in pausedTrusts) {
            val p = pausedQuic(client(trust = trust), mustStaple)
            try {
                val f = assertIs<DriveResult.Failed>(p.cs.last, "$trust: the client refuses")
                assertEquals(113, f.alert, "$trust")
                assertEquals(VerifyReason.UnknownRevocationStatus, assertIs<TlsException.Verify>(f.exception).reason, "$trust")
            } finally {
                p.close()
            }
        }
    }

    /** With its staple the must-staple leaf passes on every path; `Off` asks for nothing and requires nothing. */
    @Test fun mustStapleLeafWithItsStaplePassesOnEveryTrustPath() {
        val stapled = server(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey, OcspStapling(RevocationCerts.ocspMustStaple))
        for (trust in pausedTrusts) {
            for ((policy, srv) in listOf(RevocationPolicy.StapledIfPresent to stapled, RevocationPolicy.Off to mustStaple)) {
                val p = pausedQuic(client(policy, trust), srv)
                try {
                    assertTrue(p.cs.done && p.ss.done, "$trust, $policy: ${p.cs.last}")
                } finally {
                    p.close()
                }
            }
        }
    }

    /**
     * Once the client asks for a staple on the pause path it checks what arrives (RFC 6066 section 8: a client "MUST check
     * the OCSP response and abort the handshake if the response is not satisfactory"): a revoked staple fails there too.
     */
    @Test fun negative_revokedStapleFailsOnThePausePath() {
        val revoked = server(RevocationCerts.rvLeafRevoked, RevocationCerts.rvLeafRevokedKey, OcspStapling(RevocationCerts.ocspRevoked))
        val p = pausedQuic(client(trust = pausedTrusts.first()), revoked)
        try {
            val f = assertIs<DriveResult.Failed>(p.cs.last, "the client refuses")
            assertEquals(VerifyReason.Revoked, assertIs<TlsException.Verify>(f.exception).reason)
        } finally {
            p.close()
        }
    }

    /** A platform or application verifier keeps its own revocation behaviour; requiring a staple there is refused. */
    @Test fun negative_requireStapledNeedsKslVerifier() {
        val custom = TrustConfig.Custom(CertificateVerifier { chain, _, _ -> VerifyResult.Accepted(chain) })
        assertFailsWith<TlsException.Config> { KslQuicCrypto.newSession(client(RevocationPolicy.RequireStapled, custom)).close() }
    }

    /** The tickets a QUIC client receives from a handshake against [server] (0-RTT sessions, the ones that issue tickets). */
    private fun quicTickets(
        client: QuicTlsSession,
        server: QuicTlsSession,
    ): List<QuicSessionTicket> {
        assertTrue(server.enableEarlyData(byteArrayOf(1), null))
        client.setTransportParameters(Fixtures.tp)
        server.setTransportParameters(Fixtures.tp)
        val got = ArrayList<QuicSessionTicket>()
        val p = Pump(client, server)
        p.onEvent = { fromClient, ev -> if (fromClient && ev is TlsEvent.SessionTicket) got += ev.ticket }
        try {
            p.run()
            assertTrue(p.cs.done && p.ss.done, "the handshake completes: ${p.cs.last}")
        } finally {
            p.close()
        }
        return got
    }

    /**
     * A resumption the server declines runs a full handshake: the new ticket carries that handshake's chain and staple bound,
     * not the declined ticket's.
     */
    @Test fun negative_declinedResumptionTicketCarriesTheNewStaple() {
        val first = quicTickets(KslQuicCrypto.newSession(client(), earlyData = true), KslQuicCrypto.newSession(server(), earlyData = true))
        val old = first.last()
        first.dropLast(1).forEach { it.close() }
        assertEquals(0L, old.entry.stapleUntil, "no staple on the first server")
        // another server with its own ticket keys: it cannot decrypt the ticket and runs a full handshake, stapling this time
        val keys = listOf(ByteArray(80) { (it * 7 + 3).toByte() })
        val other =
            Fixtures.server(listOf(RevocationCerts.rvLeaf, RevocationCerts.rvMid), RevocationCerts.rvLeafKey) {
                ocspStapling = good
                sessionTickets = SessionTicketConfig(keys)
            }
        val c = KslQuicCrypto.newSession(client(), earlyData = true)
        assertTrue(c.resume(old), "the client offers the ticket")
        val fresh = quicTickets(c, KslQuicCrypto.newSession(other, earlyData = true))
        try {
            assertTrue(fresh.isNotEmpty())
            assertTrue(fresh.all { it.entry.stapleUntil > nowSeconds() }, "the staple the full handshake checked bounds the new ticket")
        } finally {
            fresh.forEach { it.close() }
        }
    }

    // ---- TCP ----

    private suspend fun tcp(
        client: TlsConfig,
        server: TlsConfig,
        cache: SessionCache = caches.new(),
    ): Pair<TlsConnection, TlsConnection> {
        val (cd, sd) = connect(client, server, clientCache = cache)
        return withTimeout(20.seconds) { cd.await() to sd.await() }
    }

    private fun tcpClient(policy: RevocationPolicy = RevocationPolicy.StapledIfPresent) =
        TcpFixtures.client {
            trust = anchored
            revocation = policy
        }

    private fun tcpServer(
        leaf: ByteArray = RevocationCerts.rvLeaf,
        key: ByteArray = RevocationCerts.rvLeafKey,
        stapling: OcspStapling? = null,
        v12: Boolean = false,
    ) = TcpFixtures.server {
        identity = TlsIdentity.fromDer(listOf(leaf, RevocationCerts.rvMid), key.copyOf())
        ocspStapling = stapling
        if (v12) versions = TlsVersions.Tls12And13
    }

    @Test fun tcpStapledGoodPasses(): Unit =
        runBlocking {
            for (v12 in listOf(false, true)) {
                val client =
                    TcpFixtures.client {
                        trust = anchored
                        revocation = RevocationPolicy.RequireStapled
                        if (v12) versions = TlsVersions.Tls12And13
                    }
                val (c, s) = tcp(client, tcpServer(stapling = good, v12 = v12))
                c.close()
                s.close()
            }
        }

    @Test fun negative_tcpStapledRevokedFails(): Unit =
        runBlocking {
            for (v12 in listOf(false, true)) {
                val client =
                    TcpFixtures.client {
                        trust = anchored
                        if (v12) versions = TlsVersions.Tls12And13
                    }
                val (cd, sd) =
                    connect(
                        client,
                        tcpServer(
                            RevocationCerts.rvLeafRevoked,
                            RevocationCerts.rvLeafRevokedKey,
                            OcspStapling(RevocationCerts.ocspRevoked),
                            v12,
                        ),
                        clientCache = caches.new(),
                    )
                val e = assertFailsWith<TlsException.Verify> { withTimeout(20.seconds) { cd.await() } }
                assertEquals(VerifyReason.Revoked, e.reason, "TLS ${if (v12) "1.2" else "1.3"}")
                runCatching { withTimeout(20.seconds) { sd.await() }.close() }
            }
        }

    @Test fun negative_tcpRequiredStapleMissing(): Unit =
        runBlocking {
            val (cd, sd) = connect(tcpClient(RevocationPolicy.RequireStapled), tcpServer(), clientCache = caches.new())
            val e = assertFailsWith<TlsException.Verify> { withTimeout(20.seconds) { cd.await() } }
            assertEquals(VerifyReason.UnknownRevocationStatus, e.reason)
            runCatching { withTimeout(20.seconds) { sd.await() }.close() }
        }

    /** TCP: the outcome of a RequireStapled client against [server]; null when it passed, else the reason. */
    private suspend fun requiredStapleOutcome(server: TlsConfig): VerifyReason? {
        val (cd, sd) = connect(tcpClient(RevocationPolicy.RequireStapled), server, clientCache = caches.new())
        return try {
            val c = withTimeout(20.seconds) { cd.await() }
            c.close()
            runCatching { withTimeout(20.seconds) { sd.await() }.close() }
            null
        } catch (e: TlsException.Verify) {
            runCatching { withTimeout(20.seconds) { sd.await() }.close() }
            e.reason
        }
    }

    private fun sniServer(override: () -> ServerTlsOverride) =
        TcpFixtures.server {
            identity = TlsIdentity.fromDer(listOf(RevocationCerts.rvLeaf, RevocationCerts.rvMid), RevocationCerts.rvLeafKey.copyOf())
            ocspStapling = good
            sniSelector = { override() }
        }

    private fun overrideIdentity(
        leaf: ByteArray,
        key: ByteArray,
    ) = TlsIdentity.fromDer(listOf(leaf, RevocationCerts.rvMid), key.copyOf())

    /**
     * Over QUIC as over TCP ([negative_sniOverrideStaplesItsOwnResponseOnly]): an identity chosen by sniSelector staples its
     * own response, and never the default identity's.
     */
    @Test fun negative_quicSniOverrideStaplesItsOwnResponseOnly() {
        fun sniServer(override: () -> ServerTlsOverride) =
            Fixtures.server(listOf(RevocationCerts.rvLeaf, RevocationCerts.rvMid), RevocationCerts.rvLeafKey) {
                ocspStapling = good
                sniSelector = { override() }
            }
        val own =
            sniServer {
                ServerTlsOverride(
                    overrideIdentity(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey),
                    null,
                    null,
                    null,
                    OcspStapling(RevocationCerts.ocspMustStaple),
                )
            }
        quicPasses(client(RevocationPolicy.RequireStapled), own)
        // the same certificate as the default identity, without a response of its own: the default's is not stapled
        val none = sniServer { ServerTlsOverride(overrideIdentity(RevocationCerts.rvLeaf, RevocationCerts.rvLeafKey)) }
        assertEquals(VerifyReason.UnknownRevocationStatus, quicRefused(client(RevocationPolicy.RequireStapled), none))
        quicPasses(
            client(RevocationPolicy.RequireStapled),
            sniServer {
                ServerTlsOverride(overrideIdentity(RevocationCerts.rvLeaf, RevocationCerts.rvLeafKey), null, null, null, good)
            },
        )
    }

    /**
     * An identity chosen by sniSelector staples its own response, and never the default identity's (TCP; QUIC:
     * [negative_quicSniOverrideStaplesItsOwnResponseOnly]).
     */
    @Test fun negative_sniOverrideStaplesItsOwnResponseOnly(): Unit =
        runBlocking {
            val own =
                sniServer {
                    ServerTlsOverride(
                        overrideIdentity(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey),
                        null,
                        null,
                        null,
                        OcspStapling(RevocationCerts.ocspMustStaple),
                    )
                }
            assertEquals(null, requiredStapleOutcome(own), "the override's own response is stapled")
            // the same certificate as the default identity, without a response of its own: the default's is not stapled
            val none = sniServer { ServerTlsOverride(overrideIdentity(RevocationCerts.rvLeaf, RevocationCerts.rvLeafKey)) }
            assertEquals(VerifyReason.UnknownRevocationStatus, requiredStapleOutcome(none))
        }

    /** A session resumes only while the response its full handshake checked is fresh, and never without one when required. */
    @Test fun negative_staleCachedStapleIsNotResumed() {
        val now = nowSeconds()

        fun fresh(
            policy: RevocationPolicy,
            until: Long,
        ): Boolean {
            val lease = KslContext.create(client(policy), quic = false)
            try {
                return lease.ctx.cachedStapleStillFresh(SessionCache.Entry(0L, emptyList(), emptyList(), stapleUntil = until))
            } finally {
                lease.close()
            }
        }
        assertTrue(fresh(RevocationPolicy.StapledIfPresent, now + 3600))
        assertFalse(fresh(RevocationPolicy.StapledIfPresent, now - 1), "past nextUpdate: a full handshake fetches a fresh one")
        assertTrue(fresh(RevocationPolicy.StapledIfPresent, 0), "none was required")
        assertFalse(fresh(RevocationPolicy.RequireStapled, 0))
        assertTrue(fresh(RevocationPolicy.Off, now - 1))
    }

    // ---- CRLs ----

    private val midCrl = CertificateRevocationList(RevocationCerts.crlMid)
    private val withCrl = TrustConfig.AnchoredCa(listOf(root), listOf(midCrl))

    @Test fun negative_crlRevokedLeafFails() {
        quicPasses(client(RevocationPolicy.Off, withCrl), server())
        val r =
            quicRefused(client(RevocationPolicy.Off, withCrl), server(RevocationCerts.rvLeafRevoked, RevocationCerts.rvLeafRevokedKey), 44)
        assertEquals(VerifyReason.Revoked, r)
    }

    @Test fun negative_expiredCrlFails() {
        val stale = TrustConfig.AnchoredCa(listOf(root), listOf(CertificateRevocationList(RevocationCerts.crlMidStale)))
        assertEquals(VerifyReason.UnknownRevocationStatus, quicRefused(client(RevocationPolicy.Off, stale), server(), 45))
    }

    @Test fun negative_unsupportedCrlsRefusedWhenTheTrustIsMade() {
        for (der in listOf(RevocationCerts.crlMidDelta, RevocationCerts.crlMidIndirect)) {
            assertFailsWith<TlsException.Config> { TrustConfig.AnchoredCa(listOf(root), listOf(CertificateRevocationList(der))) }
        }
    }

    @Test fun negative_crlThatDoesNotVerifyFails() {
        val tampered = RevocationCerts.crlMid.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        // OpenSSL's alerts (statem_lib.c ssl_x509err2alert): CRL_SIGNATURE_FAILURE decrypt_error (51), UNABLE_TO_GET_CRL unknown_ca (48)
        for ((der, alert) in listOf(tampered to 51, RevocationCerts.crlMidImpostor to 48)) {
            val trust = TrustConfig.AnchoredCa(listOf(root), listOf(CertificateRevocationList(der)))
            val p = quic(client(RevocationPolicy.Off, trust), server())
            try {
                val f = assertIs<DriveResult.Failed>(p.cs.last, "a CRL whose signature does not verify fails closed")
                assertEquals(VerifyReason.UnknownRevocationStatus, assertIs<TlsException.Verify>(f.exception).reason)
                assertEquals(alert, f.alert)
            } finally {
                p.close()
            }
        }
    }

    /** A configured CRL whose issuer is not among the roots or on the path: that issuer's certificates fail closed. */
    @Test fun negative_crlIssuerOutsideThePathFails() {
        val trust =
            TrustConfig.AnchoredCa(listOf(Certificate(RevocationCerts.rvMid)), listOf(CertificateRevocationList(RevocationCerts.crlRoot)))
        assertEquals(VerifyReason.UnknownRevocationStatus, quicRefused(client(RevocationPolicy.Off, trust), server(), 51))
    }

    @Test fun negative_crlNotCoveringTheLeafFails() {
        val trust = TrustConfig.AnchoredCa(listOf(root), listOf(CertificateRevocationList(RevocationCerts.crlMidPartitioned)))
        val p = quic(client(RevocationPolicy.Off, trust), server())
        try {
            val f = assertIs<DriveResult.Failed>(p.cs.last)
            assertEquals(VerifyReason.UnknownRevocationStatus, assertIs<TlsException.Verify>(f.exception).reason)
            assertEquals(46, f.alert, "DIFFERENT_CRL_SCOPE: certificate_unknown (OpenSSL's default)")
        } finally {
            p.close()
        }
    }

    @Test fun crlsChangeTheTrustKey() {
        assertNotEquals(anchored.derKey, withCrl.derKey)
        assertEquals(withCrl.derKey, TrustConfig.AnchoredCa(listOf(root), listOf(midCrl)).derKey)
        assertFailsWith<TlsException.Config> {
            TrustConfig.AnchoredCa(
                listOf(root),
                listOf(CertificateRevocationList(byteArrayOf(0x30, 0))),
            )
        }
    }

    @Test fun negative_reloadedCrlRefusesRevokedClient(): Unit =
        runBlocking {
            val r = TrustConfig.reloadable(anchored)
            val server =
                TcpFixtures.server {
                    clientAuth = ClientAuth.Required
                    trust = r
                }
            val revokedClient =
                TcpFixtures.client {
                    identity =
                        TlsIdentity.fromDer(
                            listOf(RevocationCerts.rvClientRevoked, RevocationCerts.rvMid),
                            RevocationCerts.rvClientRevokedKey.copyOf(),
                        )
                }
            val (c1, s1) = tcp(revokedClient, server)
            c1.close()
            s1.close()
            r.reload(withCrl)
            val (cd, sd) = connect(revokedClient, server, clientCache = caches.new())
            val e = assertFailsWith<TlsException.Verify> { withTimeout(20.seconds) { sd.await() } }
            assertEquals(VerifyReason.Revoked, e.reason)
            runCatching { withTimeout(20.seconds) { cd.await() }.close() }
        }

    @Test fun crlPemParses() {
        val pem =
            "-----BEGIN X509 CRL-----\n" +
                kotlin.io.encoding.Base64.Mime
                    .encode(RevocationCerts.crlMid) + "\n-----END X509 CRL-----\n"
        assertEquals(listOf(midCrl), CertificateRevocationList.parsePem(pem))
        assertFailsWith<TlsException.Config> { CertificateRevocationList.parsePem("nothing") }
    }
}
