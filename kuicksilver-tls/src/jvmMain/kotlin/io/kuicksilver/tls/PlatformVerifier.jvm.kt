// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import java.security.KeyStore
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathBuilderException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal actual val platformTrustViaOpenSsl: Boolean = false

/** JVM: the default `X509TrustManager` (honours `javax.net.ssl.trustStore`); it never checks the host name, `ksl` does. */
internal actual object PlatformVerifier {
    actual suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult = JvmTrust.verifyWith(JvmTrust.defaultTrustManager(), chain, role)
}

internal object JvmTrust {
    fun defaultTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    fun verifyWith(
        tm: X509TrustManager,
        chain: List<Certificate>,
        role: TlsRole,
    ): VerifyResult {
        val cf = CertificateFactory.getInstance("X.509")
        val x509 = chain.map { cf.generateCertificate(it.der.inputStream()) as X509Certificate }.toTypedArray()
        val authType = if (x509[0].publicKey.algorithm == "EC") "ECDHE_ECDSA" else "ECDHE_RSA"
        return try {
            if (role == TlsRole.Client) tm.checkServerTrusted(x509, authType) else tm.checkClientTrusted(x509, authType)
            VerifyResult.Accepted(validatedPath(tm, x509))
        } catch (e: CertificateException) {
            VerifyResult.Rejected(reasonOf(e))
        }
    }

    /**
     * The chain the trust decision rests on: a PKIX path built from the leaf through the presented certificates to one
     * of the manager's accepted issuers. Unrelated certificates a peer appends never appear in it (pins must not match
     * them). Falls back to the leaf alone when the path cannot be rebuilt (e.g. a custom manager without issuers).
     */
    private fun validatedPath(
        tm: X509TrustManager,
        presented: Array<X509Certificate>,
    ): List<Certificate> {
        val anchors = tm.acceptedIssuers.map { TrustAnchor(it, null) }.toSet()
        if (anchors.isEmpty()) return listOf(Certificate(presented[0].encoded))
        return try {
            val params = PKIXBuilderParameters(anchors, X509CertSelector().apply { certificate = presented[0] })
            params.isRevocationEnabled = false
            params.addCertStore(CertStore.getInstance("Collection", CollectionCertStoreParameters(presented.toList())))
            val result = CertPathBuilder.getInstance("PKIX").build(params) as PKIXCertPathBuilderResult
            result.certPath.certificates.map { Certificate((it as X509Certificate).encoded) } +
                Certificate(result.trustAnchor.trustedCert.encoded)
        } catch (_: CertPathBuilderException) {
            listOf(Certificate(presented[0].encoded))
        }
    }

    internal fun reasonOf(e: CertificateException): VerifyReason {
        val cause =
            generateSequence<Throwable>(
                e,
            ) { it.cause }.firstOrNull { it is CertPathValidatorException } as? CertPathValidatorException
        return when {
            e is CertificateExpiredException || cause?.reason == CertPathValidatorException.BasicReason.EXPIRED -> VerifyReason.Expired

            cause?.reason == CertPathValidatorException.BasicReason.NOT_YET_VALID -> VerifyReason.NotYetValid

            cause?.reason == CertPathValidatorException.BasicReason.REVOKED -> VerifyReason.Revoked

            cause?.reason == CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS -> VerifyReason.UnknownRevocationStatus

            cause?.reason == CertPathValidatorException.BasicReason.INVALID_SIGNATURE -> VerifyReason.BadSignature

            e.message?.contains("Pin verification failed") == true -> VerifyReason.PinMismatch(emptyList())

            // Android NSC pin-set
            else -> VerifyReason.UnknownIssuer
        }
    }
}

/** Migration from `https { trustManager = ... }`: the given manager decides trust; the name is still checked by the shared matcher. */
public fun TrustConfig.Companion.fromTrustManager(trustManager: X509TrustManager): TrustConfig =
    @OptIn(io.kuicksilver.annotations.DelicateKuicksilverApi::class)
    TrustConfig.Custom {
        chain,
        _,
        role,
        ->
        JvmTrust.verifyWith(trustManager, chain, role)
    }
