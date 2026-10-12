// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import android.net.http.X509TrustManagerExtensions
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal actual val platformTrustViaOpenSsl: Boolean = false

/**
 * Android: `TrustManagerFactory.init(null)` so the Network Security Config applies, and the host-aware
 * `X509TrustManagerExtensions.checkServerTrusted(chain, authType, host)`, which per-domain NSC requires and which returns
 * the validated chain (pins are compared against it). Client certificates are not verified by the platform in v1.
 */
internal actual object PlatformVerifier {
    actual suspend fun verify(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
    ): VerifyResult {
        if (role ==
            TlsRole.Server
        ) {
            return VerifyResult.Rejected(VerifyReason.Custom("platform client-certificate trust is not supported on Android in v1"))
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
        val cf = CertificateFactory.getInstance("X.509")
        val x509 = chain.map { cf.generateCertificate(it.der.inputStream()) as X509Certificate }.toTypedArray()
        val authType = if (x509[0].publicKey.algorithm == "EC") "ECDHE_ECDSA" else "ECDHE_RSA"
        return try {
            val validated = X509TrustManagerExtensions(tm).checkServerTrusted(x509, authType, host.value)
            VerifyResult.Accepted(validated.map { Certificate(it.encoded) })
        } catch (e: CertificateException) {
            val msg = e.message ?: ""
            VerifyResult.Rejected(
                when {
                    msg.contains("Pin verification failed") -> VerifyReason.PinMismatch(emptyList())
                    msg.contains("expired", ignoreCase = true) -> VerifyReason.Expired
                    msg.contains("blocklisted", ignoreCase = true) || msg.contains("blacklisted", ignoreCase = true) -> VerifyReason.Revoked
                    // the platform CT policy (Android 16+, NSC <certificateTransparency>) names it in the message
                    msg.contains("transparency", ignoreCase = true) -> VerifyReason.CertificateTransparency
                    else -> VerifyReason.UnknownIssuer
                },
            )
        }
    }
}
