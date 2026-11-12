// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalAtomicApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * How a client treats the revocation status of the server's certificate that the server staples (OCSP, RFC 6066 section 8
 * and RFC 9846 section 4.5.1.1), the strategy RFC 9325 section 7.5 asks for ("TLS implementations MUST implement a strategy
 * to distrust revoked certificates"). It applies where `ksl`'s own verifier checks the chain: [TrustConfig.AnchoredCa], and
 * [TrustConfig.Platform] on Linux Native, also inside [TrustConfig.Pinned] and [TrustConfig.ExpectedName]. Elsewhere the
 * platform verifier keeps its own revocation behaviour ([TrustConfig.Platform] on the JVM, Android, Apple and Windows), and a
 * [TrustConfig.Custom] or [TrustConfig.Tofu] decides alone; [RequireStapled] is refused there.
 *
 * A stapled response is checked as RFC 6960 section 3.2 says: it names the server's certificate and the issuer the verifier
 * trusted, its signature verifies under that issuer's key or a delegated responder's (id-kp-OCSPSigning, issued by that
 * issuer), and it is inside its validity interval (5 minutes of clock skew; one day after thisUpdate when it has no
 * nextUpdate). RFC 6066 section 8: a client "MUST check the OCSP response and abort the handshake if the response is not
 * satisfactory with bad_certificate_status_response(113) alert", so under every policy but [Off] a stapled response that
 * says revoked ([VerifyReason.Revoked]) or fails a check ([VerifyReason.InvalidStatusResponse]) ends the handshake with
 * that alert. A certificate with the TLS feature extension `status_request` (RFC 7633, must-staple) needs a good stapled
 * response under every policy but [Off].
 */
@ExperimentalKuicksilverApi
public enum class RevocationPolicy {
    /** No `status_request` is sent and nothing is checked; configured CRLs still apply. */
    Off,

    /**
     * The default: ask for a stapled response and check it when the server sends one; a server that staples nothing, or a
     * response that says "unknown", passes. RFC 9325 section 7.5: OCSP clients "typically 'soft-fail'", and a server "can
     * simply ignore the client's request for a stapled OCSP response", so failing without one would refuse every server
     * that does not staple.
     */
    StapledIfPresent,

    /** A stapled response that says "good" is required: none, or "unknown", fails with [VerifyReason.UnknownRevocationStatus]. */
    RequireStapled,
}

/**
 * A certificate revocation list (RFC 5280 section 5) in DER form, for [TrustConfig.AnchoredCa]: every certificate on a path
 * that trust verifies is checked against the CRL of its issuer, when one of the configured CRLs is. The CRL itself is
 * checked when a handshake uses it (its signature under the issuer's key, thisUpdate and nextUpdate): an expired CRL fails
 * every handshake whose path it covers ([VerifyReason.UnknownRevocationStatus]), so replace it before its nextUpdate
 * ([TrustConfig.ReloadableCa] on a server).
 *
 * @throws IllegalArgumentException when [der] does not start a DER SEQUENCE; the CRL is parsed when a trust is made with it.
 */
@ExperimentalKuicksilverApi
public class CertificateRevocationList(
    der: ByteArray,
) {
    /** The DER bytes, copied on construction and never handed out. */
    internal val encoded: ByteArray = der.copyOf()

    /** The DER encoding; a fresh copy on every read. */
    public val der: ByteArray get() = encoded.copyOf()

    init {
        require(encoded.isNotEmpty() && encoded[0] == 0x30.toByte()) { "a CRL is a DER SEQUENCE" }
    }

    /** Equal when the encoded CRLs are. */
    override fun equals(other: Any?): Boolean = other is CertificateRevocationList && other.encoded.contentEquals(encoded)

    /** Consistent with [equals]. */
    override fun hashCode(): Int = encoded.contentHashCode()

    /** For logs. */
    override fun toString(): String = "CertificateRevocationList(${encoded.size} bytes)"

    /** Holds [parsePem]. */
    public companion object {
        /** Every `X509 CRL` block of [pem] in order; [TlsException.Config] for damaged PEM or a text without one. */
        public fun parsePem(pem: String): List<CertificateRevocationList> {
            val blocks =
                try {
                    Pem.blocks(pem, "X509 CRL")
                } catch (e: IllegalArgumentException) {
                    throw TlsException.Config("malformed PEM: ${e.message}")
                }
            if (blocks.isEmpty()) throw TlsException.Config("no X509 CRL block in PEM")
            return blocks.map {
                try {
                    CertificateRevocationList(it)
                } catch (e: IllegalArgumentException) {
                    throw TlsException.Config("malformed CRL DER")
                }
            }
        }
    }
}

/**
 * Checks that `ksl` takes [crls] next to [roots] (each CRL parses); throws [TlsException.Config] otherwise. Run when a trust
 * with CRLs is made, so a damaged CRL fails there and a [TrustConfig.ReloadableCa] reload to it changes nothing.
 */
internal fun checkCrls(
    roots: List<Certificate>,
    crls: List<CertificateRevocationList>,
) {
    if (crls.isEmpty()) return
    KslLoader.ensureLoaded()
    val h = Ksl.ctxNew(KslConst.CLIENT)
    try {
        Ksl.ctxSetRoots(h, roots.map { it.encoded })
        Ksl.ctxSetCrls(h, crls.map { it.encoded })
    } catch (e: KslException.Internal) {
        throw TlsException.Config("CRL refused: ${e.message}")
    } finally {
        Ksl.ctxFree(h)
    }
}

/**
 * The OCSP response (RFC 6960, DER `OCSPResponse`) a server staples for its certificate (RFC 6066 section 8; in TLS 1.3 in
 * the leaf's CertificateEntry, RFC 9846 section 4.5.1.1), which RFC 9325 section 7.5 asks servers to support. Set on a
 * server's [TlsConfig.Builder.ocspStapling]; [update] replaces the response at run time (fetch a fresh one from the CA's
 * responder before the current one's nextUpdate). Each handshake takes the [current] response when the ClientHello arrives,
 * and staples it only when the client asked for it and the response is for the certificate the handshake presents (its issuer
 * the certificate of the configured chain that issued it), verifies, and is inside its validity interval at that moment: a
 * stale response, or one for another certificate (after the identity was reloaded), is never sent, and the handshake goes on
 * without one.
 */
@ExperimentalKuicksilverApi
public class OcspStapling(
    response: ByteArray? = null,
) {
    private val ref = AtomicReference(response?.let { checked(it) })

    /** The response handshakes staple from now on, a copy; null for none. */
    public val current: ByteArray? get() = ref.load()?.copyOf()

    /** The response itself, for the sessions (never handed out). */
    internal val currentForSession: ByteArray? get() = ref.load()

    /**
     * Makes [response] (null: none) the one later handshakes staple; connections already established are not affected.
     *
     * @throws TlsException.Config when [response] is empty, larger than 2^24 - 1 bytes, or not a DER SEQUENCE; [current] stays.
     */
    public fun update(response: ByteArray?) {
        ref.store(response?.let { checked(it) })
    }

    /**
     * Whether [current] would be stapled for [chain] (leaf first, its issuer next) now: the RFC 6960 checks a handshake runs.
     * For monitoring, so a response can be refreshed before it goes stale.
     */
    public fun isUsableFor(chain: List<Certificate>): Boolean {
        val r = ref.load() ?: return false
        if (chain.size < 2) return false
        KslLoader.ensureLoaded()
        val v = Ksl.ocspCheck(r, chain.take(2).map { it.encoded }, 0)
        return v.status == KslConst.OCSP_GOOD || v.status == KslConst.OCSP_REVOKED || v.status == KslConst.OCSP_UNKNOWN
    }

    private fun checked(r: ByteArray): ByteArray {
        if (r.isEmpty() || r.size > MAX_RESPONSE || r[0] != 0x30.toByte()) {
            throw TlsException.Config("an OCSP response is a DER SEQUENCE of 1..${MAX_RESPONSE} bytes")
        }
        return r.copyOf()
    }

    /** For logs. */
    override fun toString(): String = "OcspStapling(${ref.load()?.size ?: 0} bytes)"

    private companion object {
        /** RFC 6066 section 8: `opaque OCSPResponse<1..2^24-1>`. */
        const val MAX_RESPONSE = (1 shl 24) - 1
    }
}
