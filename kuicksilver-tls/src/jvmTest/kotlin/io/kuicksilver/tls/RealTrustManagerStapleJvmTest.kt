// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.runBlocking
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The staple check of the pause path under a real platform-style verifier: a [TrustConfig.Custom] whose verifier is the JDK's
 * PKIX `X509TrustManager` over a keystore holding the revocation PKI's root, run through the session's own [QuicTlsSession.verifyPeer]
 * (not a test stand-in). The trust manager checks no revocation itself (the JDK default), so what fails here is `ksl`'s staple
 * check against the issuer of the path the trust manager accepted (RFC 6066 section 8, RFC 7633 section 4.3.3).
 */
class RealTrustManagerStapleJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val trustManager: X509TrustManager by lazy {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        val cf = CertificateFactory.getInstance("X.509")
        ks.setCertificateEntry("rv-root", cf.generateCertificate(RevocationCerts.rvRoot.inputStream()))
        val f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        f.init(ks)
        f.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    /** The trust manager's verdict on the presented chain; the validated chain is the presented one (it holds rv-mid). */
    private val jdk =
        TrustConfig.Custom(
            CertificateVerifier { chain, _, _ ->
                val cf = CertificateFactory.getInstance("X.509")
                val x509 = chain.map { cf.generateCertificate(it.encoded.inputStream()) as X509Certificate }.toTypedArray()
                try {
                    trustManager.checkServerTrusted(x509, "UNKNOWN")
                    VerifyResult.Accepted(chain)
                } catch (_: CertificateException) {
                    VerifyResult.Rejected(VerifyReason.UnknownIssuer)
                }
            },
        )

    private fun handshake(
        leaf: ByteArray,
        key: ByteArray,
        staple: ByteArray?,
    ): Pump {
        val client = KslQuicCrypto.newSession(Fixtures.client(jdk) { revocation = RevocationPolicy.StapledIfPresent })
        val server =
            KslQuicCrypto.newSession(
                Fixtures.server(listOf(leaf, RevocationCerts.rvMid), key) { ocspStapling = staple?.let { OcspStapling(it) } },
            )
        client.setTransportParameters(Fixtures.tp)
        server.setTransportParameters(Fixtures.tp)
        val p = Pump(client, server)
        p.run(onVerify = { runBlocking { client.verifyPeer(it.chain) } })
        return p
    }

    private fun refusedWith(p: Pump): VerifyReason =
        try {
            val f = assertIs<DriveResult.Failed>(p.cs.last, "the client refuses")
            assertEquals(113, f.alert)
            assertIs<TlsException.Verify>(f.exception).reason
        } finally {
            p.close()
        }

    @Test fun negative_mustStapleLeafWithoutStapleFailsUnderTheJdkTrustManager() {
        assertEquals(
            VerifyReason.UnknownRevocationStatus,
            refusedWith(handshake(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey, null)),
        )
    }

    @Test fun negative_revokedStapleFailsUnderTheJdkTrustManager() {
        assertEquals(
            VerifyReason.Revoked,
            refusedWith(handshake(RevocationCerts.rvLeafRevoked, RevocationCerts.rvLeafRevokedKey, RevocationCerts.ocspRevoked)),
        )
    }

    @Test fun goodStaplesPassUnderTheJdkTrustManager() {
        for ((leaf, key, staple) in listOf(
            Triple(RevocationCerts.rvLeafMustStaple, RevocationCerts.rvLeafMustStapleKey, RevocationCerts.ocspMustStaple),
            Triple(RevocationCerts.rvLeaf, RevocationCerts.rvLeafKey, RevocationCerts.ocspGood),
        )) {
            val p = handshake(leaf, key, staple)
            try {
                assertTrue(p.cs.done && p.ss.done, "${p.cs.last}")
            } finally {
                p.close()
            }
        }
    }
}
