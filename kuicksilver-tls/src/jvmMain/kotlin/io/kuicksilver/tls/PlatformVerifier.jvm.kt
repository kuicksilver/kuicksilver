// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.cert.CertPathBuilder
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal actual val platformTrustViaOpenSsl: Boolean = false

/**
 * JVM: the default `X509TrustManager` (honours `javax.net.ssl.trustStore`); it never checks the host name, `ksl` does.
 * [offline] (a name an accepted Encrypted Client Hello hid, RFC 9849 section 10.7): the same anchors, checked by this
 * connection's own path validation over the presented certificates, which makes no network request ([JvmTrust.offline]).
 */
internal actual object PlatformVerifier {
    actual suspend fun evaluate(
        chain: List<Certificate>,
        host: HostName,
        role: TlsRole,
        offline: Boolean,
    ): PlatformVerdict = JvmTrust.evaluate(JvmTrust.defaultTrustManager(), chain, role, offline)
}

internal object JvmTrust {
    /** [evaluateWith] under [base], or [offline] under its anchors when [offline] is set. */
    fun evaluate(
        base: X509TrustManager,
        chain: List<Certificate>,
        role: TlsRole,
        offline: Boolean,
    ): PlatformVerdict = (if (offline) offline(base, chain, role) else null) ?: evaluateWith(base, chain, role)

    /**
     * The verdict of [base]'s anchors (its accepted issuers: the default manager's trust store) on [chain], reached without
     * a network request (RFC 9849 section 10.7: "clients SHOULD take steps to minimize or protect such requests during
     * certificate validation"): the path is built here from the presented certificates alone, each issuer found by name and
     * signature, up to one of the anchors, and checked with the JDK's PKIX `CertPathValidator` (validity, signatures, basic
     * constraints, name constraints, the `jdk.certpath.disabledAlgorithms` constraints), with revocation checking off; the
     * leaf's extended key usage must allow the role. Neither the JDK's trust manager nor its `CertPathBuilder` is used: the
     * builder fetches a missing intermediate from the AIA extension when the process set
     * `com.sun.security.enableAIAcaIssuers`, a process-wide switch, and the manager checks revocation (and fetches) when it
     * set `com.sun.net.ssl.checkRevocation`. A chain that needs an intermediate the peer did not send is refused here
     * (`UnknownIssuer`). Null (the caller asks [base]) when the default algorithm is not PKIX (`SunX509` checks no
     * revocation and fetches nothing anyway).
     */
    fun offline(
        base: X509TrustManager,
        chain: List<Certificate>,
        role: TlsRole,
    ): PlatformVerdict? {
        if (TrustManagerFactory.getDefaultAlgorithm() != "PKIX") return null
        val rejected = { r: VerifyReason -> PlatformVerdict(VerifyResult.Rejected(r), null) }
        val anchors = anchorsOf(base)
        val cf = CertificateFactory.getInstance("X.509")
        val x509 =
            try {
                chain.map { cf.generateCertificate(it.encoded.inputStream()) as X509Certificate }
            } catch (_: CertificateException) {
                return rejected(VerifyReason.UnknownIssuer)
            }
        if (x509.isEmpty()) return rejected(VerifyReason.UnknownIssuer)
        val path = arrayListOf(x509[0])
        val unused = x509.drop(1).toMutableList()
        var anchor: TrustAnchor? = null
        while (path.size <= MAX_OFFLINE_PATH) {
            val cur = path.last()
            anchor = anchors.firstOrNull { it.trustedCert.subjectX500Principal == cur.issuerX500Principal && signedBy(cur, it.trustedCert) }
            if (anchor != null) break
            val next = unused.firstOrNull { it.subjectX500Principal == cur.issuerX500Principal && signedBy(cur, it) } ?: break
            unused -= next
            path += next
        }
        if (anchor == null) return rejected(VerifyReason.UnknownIssuer)
        return try {
            val params = PKIXParameters(setOf(anchor))
            params.isRevocationEnabled = false
            CertPathValidator.getInstance("PKIX").validate(cf.generateCertPath(path), params)
            if (!ekuAllows(x509[0], role)) return rejected(VerifyReason.UnknownIssuer)
            val built = path.map { Certificate(it.encoded) } + Certificate(anchor.trustedCert.encoded)
            PlatformVerdict(VerifyResult.Accepted(built), built)
        } catch (e: CertPathValidatorException) {
            rejected(reasonOf(CertificateException(e)))
        } catch (_: GeneralSecurityException) {
            rejected(VerifyReason.UnknownIssuer)
        }
    }

    private const val MAX_OFFLINE_PATH = 10

    private fun signedBy(
        cert: X509Certificate,
        issuer: X509Certificate,
    ): Boolean =
        try {
            cert.verify(issuer.publicKey)
            true
        } catch (_: GeneralSecurityException) {
            false
        }

    /** The leaf's extended key usage allows [role]'s peer: none listed, `anyExtendedKeyUsage`, or serverAuth / clientAuth. */
    private fun ekuAllows(
        leaf: X509Certificate,
        role: TlsRole,
    ): Boolean {
        val eku =
            try {
                leaf.extendedKeyUsage
            } catch (_: java.security.cert.CertificateParsingException) {
                return false
            } ?: return true
        return "2.5.29.37.0" in eku || (if (role == TlsRole.Client) "1.3.6.1.5.5.7.3.1" else "1.3.6.1.5.5.7.3.2") in eku
    }

    fun defaultTrustManager(): X509TrustManager {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        return tmf.trustManagers.filterIsInstance<X509TrustManager>().first()
    }

    fun verifyWith(
        tm: X509TrustManager,
        chain: List<Certificate>,
        role: TlsRole,
    ): VerifyResult = evaluateWith(tm, chain, role).result

    /** [verifyWith], with the path the decision rests on ([validatedPath]) on a yes. */
    fun evaluateWith(
        tm: X509TrustManager,
        chain: List<Certificate>,
        role: TlsRole,
    ): PlatformVerdict {
        val cf = CertificateFactory.getInstance("X.509")
        val x509 = chain.map { cf.generateCertificate(it.encoded.inputStream()) as X509Certificate }.toTypedArray()
        val authType = if (x509[0].publicKey.algorithm == "EC") "ECDHE_ECDSA" else "ECDHE_RSA"
        return try {
            if (role == TlsRole.Client) tm.checkServerTrusted(x509, authType) else tm.checkClientTrusted(x509, authType)
            val built = validatedPath(tm, x509)
            PlatformVerdict(VerifyResult.Accepted(built ?: listOf(Certificate(x509[0].encoded))), built)
        } catch (e: CertificateException) {
            PlatformVerdict(VerifyResult.Rejected(reasonOf(e)), null)
        }
    }

    /**
     * The chain the trust decision rests on, leaf first and its trust anchor last. `X509TrustManager` does not hand out the
     * path it validated (`sun.security.validator.Validator` returns it, but only inside the JDK), so it is built again with the
     * JDK's PKIX `CertPathBuilder` (the builder the JDK's own `PKIXValidator` uses when the presented chain is not a straight
     * path), from the leaf through the presented certificates to one of the manager's accepted issuers, the same anchors, with
     * the JDK's algorithm constraints. Unrelated certificates a peer appends never appear in it (pins must not match them, the
     * security level does not hold on them). Null when the path cannot be rebuilt (e.g. a custom manager without issuers):
     * pins then see the leaf alone, and the security level holds on the presented chain ([platformLevel]).
     */
    private fun validatedPath(
        tm: X509TrustManager,
        presented: Array<X509Certificate>,
    ): List<Certificate>? {
        val anchors = anchorsOf(tm)
        if (anchors.isEmpty()) return null
        return try {
            val params = PKIXBuilderParameters(anchors, X509CertSelector().apply { certificate = presented[0] })
            params.isRevocationEnabled = false
            params.addCertStore(CertStore.getInstance("Collection", CollectionCertStoreParameters(presented.toList())))
            val result = CertPathBuilder.getInstance("PKIX").build(params) as PKIXCertPathBuilderResult
            result.certPath.certificates.map { Certificate((it as X509Certificate).encoded) } +
                Certificate(result.trustAnchor.trustedCert.encoded)
        } catch (_: GeneralSecurityException) {
            // CertPathBuilderException, and InvalidAlgorithmParameterException or the like from the parameters
            null
        }
    }

    /** The trust anchors of [tm], kept for the last manager asked (the default one is made per handshake, its issuers are not). */
    private fun anchorsOf(tm: X509TrustManager): Set<TrustAnchor> {
        val issuers = tm.acceptedIssuers.toList()
        lastAnchors?.let { (key, anchors) -> if (key == issuers) return anchors }
        return issuers.map { TrustAnchor(it, null) }.toSet().also { lastAnchors = issuers to it }
    }

    @Volatile private var lastAnchors: Pair<List<X509Certificate>, Set<TrustAnchor>>? = null

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
