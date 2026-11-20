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
import kotlin.test.assertTrue

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

    /**
     * The JDK's path builder fetches a missing intermediate from the AIA extension when the process set
     * `com.sun.security.enableAIAcaIssuers`, a process-wide switch: offline, the path is built from the presented
     * certificates alone and checked with a CertPathValidator, which fetches nothing. A child JVM with the switch on: the
     * online check (the control) opens the leaf's caIssuers URL, the offline one opens nothing.
     */
    @Test fun offlineFetchesNoIntermediateWithAiaOn() {
        fun probe(offline: Boolean): List<String> {
            val javaBin = java.io.File(System.getProperty("java.home"), "bin/java").path
            val p =
                ProcessBuilder(
                    javaBin,
                    "-Dcom.sun.security.enableAIAcaIssuers=true",
                    "-cp",
                    System.getProperty("java.class.path"),
                    "io.kuicksilver.tls.OfflineAiaProbeKt",
                    offline.toString(),
                ).redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readLines()
            check(p.waitFor(60, java.util.concurrent.TimeUnit.SECONDS)) { "the probe did not end" }
            check(out.any { it.startsWith("done ") }) { "the probe failed: $out" }
            return out
        }
        val online = probe(offline = false)
        assertTrue(online.any { it.startsWith("fetched http://127.0.0.1:1/ca.cer") }, "control: online fetches the issuer: $online")
        val offline = probe(offline = true)
        assertTrue(offline.none { it.startsWith("fetched") }, "offline fetches nothing: $offline")
        assertTrue(offline.any { it == "done Rejected" }, "an issuer not among the anchors is still refused: $offline")
    }

    @Test fun offlineKeepsTheAnchors() {
        val other =
            TrustManagerFactory.getInstance("PKIX").let { tmf ->
                tmf.init(null as java.security.KeyStore?)
                tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
            }
        // the system anchors do not include the test CA: offline does not widen trust
        assertIs<VerifyResult.Rejected>(JvmTrust.evaluate(other, chain, TlsRole.Client, offline = true).result)
    }
}
