// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * TLS certificate compression (RFC 8879, [TlsConfig.Builder.certificateCompression]) over QUIC and TCP: on by default with
 * brotli, client certificates too, a peer without it, and a peer's malformed CompressedCertificate (QUIC, whose handshake
 * messages the test sees in the clear and rewrites). The C suite (`test_certcomp.c`) covers every field of the message.
 */
@OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)
class CertificateCompressionTest {
    /**
     * What this platform's library compresses with: brotli and zlib, or zlib alone where it has brotli's decoder only (Android,
     * iOS; ADR-0025). A server's chain comes in [serverAlg], a client's certificate in [clientAlg] (null: uncompressed).
     */
    private val brotli = CertificateCompression.Brotli in CertificateCompression.compressors()
    private val serverAlg = if (brotli) CertificateCompression.Brotli else CertificateCompression.Zlib
    private val clientAlg = if (brotli) CertificateCompression.Brotli else null

    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() } // a TCP test resuming another's ticket would see no Certificate at all
    }

    private fun pair(
        client: TlsConfig = Fixtures.client(),
        server: TlsConfig = Fixtures.server(),
    ): Pump =
        Pump(KslQuicCrypto.newSession(client), KslQuicCrypto.newSession(server)).also {
            it.c.setTransportParameters(Fixtures.tp)
            it.s.setTransportParameters(Fixtures.tp)
        }

    private val chain = listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate)

    private fun mtlsServer(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
        Fixtures.server(chain, TestCerts.serverViaIntermediateKey) {
            clientAuth = ClientAuth.Required
            trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
            block()
        }

    private fun mtlsClient(block: TlsConfig.Builder.() -> Unit = {}): TlsConfig =
        Fixtures.client {
            identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())
            block()
        }

    @Test fun onByDefault() {
        assertTrue(Fixtures.client().certificateCompression)
        assertTrue(Fixtures.server().certificateCompression)
        assertFalse(Fixtures.client { certificateCompression = false }.certificateCompression)
    }

    @Test fun quicServerChainAndClientCertificateComeCompressedWithBrotli() {
        val p = pair(mtlsClient(), mtlsServer())
        try {
            p.run()
            assertTrue(p.cs.done && p.ss.done, "handshake")
            assertEquals(serverAlg, p.c.peerCertificateCompression, "the server's chain")
            assertEquals(clientAlg, p.s.peerCertificateCompression, "the client's certificate")
            assertEquals(chain.map(::Certificate), p.c.peerCertificates, "the chain decompressed whole")
        } finally {
            p.close()
        }
    }

    /** RFC 8879 section 3: a peer that did not offer the extension gets a plain Certificate, and the handshake completes. */
    @Test fun negative_quicPeerWithoutCompressionGetsPlainCertificates() {
        for (clientOn in listOf(false, true)) {
            val p = pair(mtlsClient { certificateCompression = clientOn }, mtlsServer { certificateCompression = !clientOn })
            try {
                p.run()
                assertTrue(p.cs.done && p.ss.done, "handshake, client compression $clientOn")
                assertNull(p.c.peerCertificateCompression, "plain server chain, client compression $clientOn")
                assertNull(p.s.peerCertificateCompression, "plain client certificate, client compression $clientOn")
            } finally {
                p.close()
            }
        }
    }

    /**
     * The server's own CompressedCertificate (brotli) with one change, delivered in place of the original: the client ends the
     * handshake with the alert RFC 8879 sections 4 and 5 give (RFC 8446 section 6.2's illegal_parameter where it names none).
     */
    private fun tampered(change: (ByteArray) -> ByteArray): DriveResult.Failed =
        rewritten(change) ?: throw AssertionError("the client completed the handshake")

    /** The client's failure under [change], null when it completed the handshake. */
    private fun rewritten(change: (ByteArray) -> ByteArray): DriveResult.Failed? {
        val c = KslQuicCrypto.newSession(Fixtures.client())
        val s = KslQuicCrypto.newSession(Fixtures.server(chain, TestCerts.serverViaIntermediateKey))
        c.setTransportParameters(Fixtures.tp)
        s.setTransportParameters(Fixtures.tp)
        val keys = ArrayList<PacketProtector>()
        var rewritten = false
        var clientDone = false
        try {
            repeat(40) {
                for ((me, peer) in listOf(c to s, s to c)) {
                    val r = me.drive()
                    if (r is DriveResult.Failed && me === c) return r
                    val handshake = ArrayList<Byte>()
                    while (true) {
                        val ev = me.nextEvent() ?: break
                        when (ev) {
                            is TlsEvent.CryptoData -> {
                                if (ev.level ==
                                    EncryptionLevel.Handshake
                                ) {
                                    handshake += ev.data.toList()
                                } else {
                                    peer.provide(ev.level, ev.data)
                                }
                            }

                            is TlsEvent.Keys -> {
                                keys += ev.protector
                            }

                            TlsEvent.HandshakeDone -> {
                                if (me === c) clientDone = true
                            }

                            else -> {}
                        }
                    }
                    if (handshake.isNotEmpty()) {
                        var bytes = handshake.toByteArray()
                        if (me === s) {
                            bytes = rewriteCompressed(bytes, change)
                            rewritten = true
                        }
                        peer.provide(EncryptionLevel.Handshake, bytes)
                    }
                }
            }
            assertTrue(rewritten, "the server's flight passed through the rewrite")
            assertTrue(clientDone, "the client neither failed nor completed")
            return null
        } finally {
            keys.forEach { it.close() }
            c.close()
            s.close()
        }
    }

    /** Replaces the CompressedCertificate (type 25) among whole handshake messages with [change] of it (header included). */
    private fun rewriteCompressed(
        flight: ByteArray,
        change: (ByteArray) -> ByteArray,
    ): ByteArray {
        val out = ArrayList<Byte>()
        var p = 0
        while (p + 4 <= flight.size) {
            val len = (flight[p + 1].toInt() and 0xff shl 16) or (flight[p + 2].toInt() and 0xff shl 8) or (flight[p + 3].toInt() and 0xff)
            val msg = flight.copyOfRange(p, p + 4 + len)
            out += (if (msg[0].toInt() == 25) change(msg) else msg).toList()
            p += 4 + len
        }
        out += flight.copyOfRange(p, flight.size).toList()
        return out.toByteArray()
    }

    private fun put24(
        b: ByteArray,
        at: Int,
        v: Int,
    ) {
        b[at] = (v ushr 16).toByte()
        b[at + 1] = (v ushr 8).toByte()
        b[at + 2] = v.toByte()
    }

    private fun get24(
        b: ByteArray,
        at: Int,
    ): Int = (b[at].toInt() and 0xff shl 16) or (b[at + 1].toInt() and 0xff shl 8) or (b[at + 2].toInt() and 0xff)

    private fun alertSent(f: DriveResult.Failed): Int? = f.alert

    @Test fun negative_wrongUncompressedLengthIsBadCertificate() {
        for (delta in listOf(1, -1)) {
            val f = tampered { m -> m.copyOf().also { put24(it, 6, get24(m, 6) + delta) } }
            assertEquals(42, alertSent(f), "uncompressed_length off by $delta: bad_certificate")
        }
    }

    @Test fun negative_uncompressedLengthAboveTheCertificateListBoundIsBadCertificate() {
        val f = tampered { m -> m.copyOf().also { put24(it, 6, 0xffffff) } }
        assertEquals(42, alertSent(f), "2^24-1 announced: refused before decompressing")
    }

    /** 1 MiB of zeros in 14 bytes of brotli, announced as the real chain's length: the output stops there, bad_certificate. */
    @Test fun negative_decompressionBombIsBadCertificate() {
        val bomb = byteArrayOf(0x59, -1, -1, -113, 0x7f, 0x02, 0x20, 0x1e, 0x0b, 0x04, 0x72, -17, 0x1f, 0x00)
        val f =
            tampered { m ->
                val head = m.copyOfRange(0, 12)
                head[4] = 0
                head[5] = 2 // brotli, whatever the server sent (zlib from a library with brotli's decoder only)
                put24(head, 1, 2 + 3 + 3 + bomb.size)
                put24(head, 9, bomb.size)
                head + bomb
            }
        assertEquals(42, alertSent(f))
    }

    /** RFC 8879 section 4: "The algorithm MUST be one of the algorithms listed in the peer's compress_certificate extension". */
    @Test fun negative_algorithmNotOfferedIsIllegalParameter() {
        for (alg in listOf(3, 0x4242)) {
            val f =
                tampered { m ->
                    m.copyOf().also {
                        it[4] = (alg ushr 8).toByte()
                        it[5] = alg.toByte()
                    }
                }
            assertEquals(47, alertSent(f), "algorithm $alg: illegal_parameter")
            assertIs<TlsException.Protocol>(f.exception)
        }
    }

    /** The control of the cases above: the message passed through the same rewrite unchanged completes the handshake. */
    @Test fun anUnchangedCompressedCertificateIsAccepted() {
        assertNull(rewritten { it.copyOf() })
    }

    /**
     * RFC 8879 section 4: the compressed message holds the Certificate "that would have been sent", over TLS 1.3 with the stapled
     * OCSP response in it. The chain compressed when the context was built has no session's response, so a session that staples
     * sends its Certificate uncompressed: the response arrives, a revoked status included. A client that asks for no status
     * gets the chain compressed (the control).
     */
    @Test fun negative_aStaplingSessionSendsItsCertificateUncompressed() {
        val anchored = TrustConfig.AnchoredCa(listOf(Certificate(RevocationCerts.rvRoot)))

        fun server(
            leaf: ByteArray,
            key: ByteArray,
            staple: ByteArray,
        ) = Fixtures.server(listOf(leaf, RevocationCerts.rvMid), key) { ocspStapling = OcspStapling(staple) }
        val good = server(RevocationCerts.rvLeaf, RevocationCerts.rvLeafKey, RevocationCerts.ocspGood)
        for ((policy, expected) in listOf(RevocationPolicy.RequireStapled to null, RevocationPolicy.Off to serverAlg)) {
            val p = pair(Fixtures.client(anchored) { revocation = policy }, good)
            try {
                p.run()
                assertTrue(p.cs.done && p.ss.done, "handshake under $policy: ${p.cs.last}")
                assertEquals(expected, p.c.peerCertificateCompression, "under $policy")
            } finally {
                p.close()
            }
        }
        val revoked = server(RevocationCerts.rvLeafRevoked, RevocationCerts.rvLeafRevokedKey, RevocationCerts.ocspRevoked)
        val p = pair(Fixtures.client(anchored), revoked)
        try {
            p.run()
            val f = assertIs<DriveResult.Failed>(p.cs.last, "a stapled revoked status still reaches the client")
            assertEquals(VerifyReason.Revoked, assertIs<TlsException.Verify>(f.exception).reason)
        } finally {
            p.close()
        }
    }

    // --- TCP ---

    @Test fun tcpServerChainAndClientCertificateComeCompressedWithBrotli() {
        val (cd, sd) =
            connect(
                TcpFixtures.client { identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()) },
                TcpFixtures.server {
                    clientAuth = ClientAuth.Required
                    trust = TrustConfig.AnchoredCa(listOf(Fixtures.testCa))
                },
            )
        runBlocking {
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals(serverAlg, c.peerCertificateCompression)
                assertEquals(clientAlg, s.peerCertificateCompression)
            } finally {
                c.close()
                s.close()
            }
        }
    }

    @Test fun negative_tcpPeerWithoutCompressionGetsPlainCertificates() {
        for (clientOn in listOf(false, true)) {
            val (cd, sd) =
                connect(
                    TcpFixtures.client { certificateCompression = clientOn },
                    TcpFixtures.server { certificateCompression = !clientOn },
                )
            runBlocking {
                val c = withTimeout(10.seconds) { cd.await() }
                val s = withTimeout(10.seconds) { sd.await() }
                try {
                    assertNull(c.peerCertificateCompression, "client compression $clientOn")
                } finally {
                    c.close()
                    s.close()
                }
            }
        }
    }

    /**
     * Peers that also allow TLS 1.2 negotiate 1.3 and compress. A TLS 1.2 handshake ignores the extension (RFC 8879 section 3)
     * and has no record compression (RFC 9325 section 3.3): the C suite checks both (`negative_certcomp_tls12_...`), as the
     * Kotlin API builds no TLS 1.2-only pair.
     */
    @Test fun tls12And13PeersCompressUnderTls13() {
        val (cd, sd) =
            connect(
                TcpFixtures.client { versions = TlsVersions.Tls12And13 },
                TcpFixtures.server { versions = TlsVersions.Tls12And13 },
            )
        runBlocking {
            val c = withTimeout(10.seconds) { cd.await() }
            val s = withTimeout(10.seconds) { sd.await() }
            try {
                assertEquals(TlsVersion.Tls13, c.protocolVersion)
                assertFalse(c.sessionReused)
                assertEquals(serverAlg, c.peerCertificateCompression)
            } finally {
                c.close()
                s.close()
            }
        }
    }

    /** A resumed TLS 1.3 handshake carries no Certificate (RFC 9846 section 4.5.1), so nothing came compressed either. */
    @Test fun aResumptionHasNoCertificateToCompress() {
        val server = TcpFixtures.server()
        val cache = SessionCache()
        repeat(2) { round ->
            val (cd, sd) = connect(TcpFixtures.client(), server, clientCache = cache)
            runBlocking {
                val c = withTimeout(10.seconds) { cd.await() }
                val s = withTimeout(10.seconds) { sd.await() }
                try {
                    // the client reads once from the server, so the ticket that follows the handshake arrives
                    s.output.writeFully(byteArrayOf(1), 0, 1)
                    s.output.flush()
                    c.input.readExactly(1)
                    assertEquals(round == 1, c.sessionReused, "round $round")
                    assertEquals(if (round == 0) serverAlg else null, c.peerCertificateCompression, "round $round")
                } finally {
                    c.close()
                    s.close()
                }
            }
        }
        runBlocking { cache.close() }
    }

    /** The override of an sniSelector keeps the base configuration's choice. */
    @Test fun anOverrideKeepsTheBaseChoice() {
        val base = TcpFixtures.server { certificateCompression = false }
        val o = base.withOverride(ServerTlsOverride(identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())))
        assertFalse(o.certificateCompression)
    }

    @Test fun algorithmOfTheGetter() {
        assertEquals(CertificateCompression.Brotli, CertificateCompression.of(byteArrayOf(0, 2)))
        assertEquals(CertificateCompression.Zlib, CertificateCompression.of(byteArrayOf(0, 1)))
        assertNull(CertificateCompression.of(byteArrayOf(0, 0)), "a plain Certificate")
        assertNull(CertificateCompression.of(byteArrayOf(0x42, 0x42)), "an algorithm this build does not know")
        assertNull(CertificateCompression.of(byteArrayOf()), "a short answer")
    }
}
