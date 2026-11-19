// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import java.security.cert.CertificateFactory
import java.security.cert.PKIXBuilderParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import javax.net.ssl.CertPathTrustManagerParameters
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertSame

/**
 * RFC 9849 section 10.7 on the JVM: the platform verifier asked to stay offline (a name an accepted ECH hid) checks the chain
 * under the same anchors with a PKIX manager of its own that makes no revocation request, even where the process turned
 * revocation checking on. The leaf's CRL and OCSP URLs point at a port nothing listens on: a manager that checks revocation
 * must try them and cannot decide; the offline one accepts without looking.
 */
class OfflineTrustJvmTest {
    private fun x509(pem: String): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(
            Certificate
                .parsePem(pem)
                .single()
                .encoded
                .inputStream(),
        )
            as X509Certificate

    /** What the default manager is when the process sets `com.sun.net.ssl.checkRevocation`: PKIX with revocation on. */
    private fun revocationChecking(): X509TrustManager {
        val params = PKIXBuilderParameters(setOf(TrustAnchor(x509(OfflineTrustCerts.CA), null)), null)
        params.isRevocationEnabled = true
        val tmf = TrustManagerFactory.getInstance("PKIX")
        tmf.init(CertPathTrustManagerParameters(params))
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    private val chain = Certificate.parsePem(OfflineTrustCerts.LEAF)

    @Test fun offlineMakesNoRevocationRequest() {
        val base = revocationChecking()
        val online = JvmTrust.evaluate(base, chain, TlsRole.Client, offline = false).result
        assertEquals(
            VerifyReason.UnknownRevocationStatus,
            assertIs<VerifyResult.Rejected>(online).reason,
            "the online manager tried the URLs",
        )
        val offline = JvmTrust.evaluate(base, chain, TlsRole.Client, offline = true).result
        assertIs<VerifyResult.Accepted>(offline, "the offline manager decided without them")
    }

    @Test fun offlineKeepsTheAnchors() {
        val other =
            TrustManagerFactory.getInstance("PKIX").let { tmf ->
                tmf.init(null as java.security.KeyStore?)
                tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
            }
        // the system anchors do not include the test CA: offline does not widen trust
        assertIs<VerifyResult.Rejected>(JvmTrust.evaluate(other, chain, TlsRole.Client, offline = true).result)
        val base = revocationChecking()
        assertSame(JvmTrust.offline(base), JvmTrust.offline(base), "made once per set of anchors")
    }
}
