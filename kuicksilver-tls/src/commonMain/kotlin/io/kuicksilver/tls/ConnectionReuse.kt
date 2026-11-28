// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst

/**
 * Whether [chain], the certificates the server of an established client connection presented (leaf first, as
 * [TlsConnection.peerCertificates] or a QUIC connection's `peerCertificates` give them; a resumed connection's are those of
 * its full handshake), passes now every check a new client connection made with this configuration would make on it: the
 * trust of [TlsConfig.trust] (the platform's verifier, the anchors and their CRLs, a [TrustConfig.Custom] verifier), the
 * pins on the validated chain, the reference identifier (the [TlsConfig.serverName], or an [TrustConfig.ExpectedName]),
 * the security level and the stapled OCSP response. It is what a client that coalesces asks before it sends a request for
 * another origin on a connection (RFC 9113 section 9.1.1: "The certificate presented by the server MUST satisfy any checks
 * that the client would perform when forming a new TLS connection for the host in the URI"; RFC 9114 section 3.3: "clients
 * MUST validate the certificate presented by the server for the new origin server using the process described in Section
 * 4.3.4 of \[HTTP\]").
 *
 * - Validity is checked at the current time, so a certificate that expired since the handshake fails with
 *   [VerifyReason.Expired].
 * - The staple: [stapleUntil] is the connection's (`TlsConnection.stapleUntil`, a QUIC connection's): with
 *   [RevocationPolicy.Off] nothing is checked; without a staple ([stapleUntil] 0) the chain passes unless
 *   [RevocationPolicy.RequireStapled] or a must-staple leaf (RFC 7633 section 4.3.3) needs one; with one, it must still be
 *   fresh now, as a resumption requires (RFC 6960 section 4.2.2.1). Otherwise [VerifyReason.UnknownRevocationStatus].
 * - [hiddenName]: the host would not appear on the path (the connection's ECH was accepted, or a new connection to the host
 *   would offer ECH): the platform's verifier makes no network request about it (RFC 9849 section 10.7), as in a handshake
 *   with ECH. A configuration that offers ECH ([TlsConfig.echConfigList]) counts as that too.
 * - The extended key usage (serverAuth) and the other purpose checks are OpenSSL's on the OpenSSL path; on the pause path
 *   (the platform's verifier, a custom one) `ksl` checks the purpose after the pause in a handshake, which this does not
 *   repeat: the purpose is a property of the leaf alone, not of the host, and the handshake that set the connection up
 *   held the same leaf to it.
 * - [TrustConfig.Tofu] always refuses ([VerifyReason.Custom]): a key is remembered for a name only from a handshake with
 *   it, and a name without one would be a first contact taken from another origin's connection.
 *
 * A client certificate the server asked for is the connection's, not the chain's, and is not looked at. A server
 * configuration throws [IllegalArgumentException].
 */
@InternalKuicksilverApi
public suspend fun TlsConfig.verifyForReuse(
    chain: List<Certificate>,
    stapleUntil: Long = 0L,
    hiddenName: Boolean = false,
): VerifyResult {
    require(role == TlsRole.Client) { "verifyForReuse checks a server's chain for a client configuration" }
    if (chain.isEmpty()) return VerifyResult.Rejected(VerifyReason.NoCertificate)
    val base = (trust as? TrustConfig.Pinned)?.base ?: trust
    if (base is TrustConfig.Tofu) {
        return VerifyResult.Rejected(
            VerifyReason.Custom("Tofu: no first contact from another origin's connection"),
        )
    }
    val verdict = verifyChainForReuse(chain, hiddenName || echConfigList?.isUsable == true)
    if (verdict is VerifyResult.Rejected) return verdict
    if (!stapleStillFresh(chain[0], stapleUntil)) return VerifyResult.Rejected(VerifyReason.UnknownRevocationStatus)
    return verdict
}

/** The staple rule of [verifyForReuse], as a resumption keeps it (`cachedStapleStillFresh`), must-staple leaves included. */
private fun TlsConfig.stapleStillFresh(
    leaf: Certificate,
    stapleUntil: Long,
): Boolean {
    if (revocation == RevocationPolicy.Off) return true
    if (stapleUntil == 0L) return revocation != RevocationPolicy.RequireStapled && !leaf.mustStaple
    return nowSeconds() + resumptionClockSkewForTest <= stapleUntil
}

private suspend fun TlsConfig.verifyChainForReuse(
    chain: List<Certificate>,
    hiddenName: Boolean,
): VerifyResult {
    val reference = HostName.normalize(referenceOf(this))
    val ders = chain.map { it.encoded }
    if (KslContext.verifyModeFor(this) == KslConst.VERIFY_OPENSSL) {
        // the anchors, CRLs, purpose, validity and name exactly as OpenSSL checks them in a handshake of this configuration
        // (`ksl_ctx_verify_chain_path`); the pins then hold on the path it built, as after an AnchoredCa handshake
        val lease = KslContext.create(this, quic = false)
        try {
            val path = ArrayList<ByteArray>()
            val err = Ksl.ctxVerifyChainPath(lease.ctx.handle, ders, reference.value, nowSeconds() + resumptionClockSkewForTest, path)
            if (err != 0) {
                return VerifyResult.Rejected(
                    verifyReasonOf(if (err > 0) err else 0, 0, chain) ?: VerifyReason.Custom("the chain did not verify ($err)"),
                )
            }
            return Verification(this).pinCheck(path.map(::Certificate))
        } finally {
            lease.close()
        }
    }
    // the pause path of a handshake: the security level walk `ksl` runs on the presented chain before the pause (the platform
    // holds it on the path it builds instead, platformLevel), the Kotlin-side trust and pins, then the shared name matcher
    // `ksl` applies after the pause (ADR-0011 rule 4)
    if (!platformDecides(trust)) {
        when (Ksl.chainLevel(ders, builtPath = false)) {
            0 -> {}

            66, 67 -> {
                return VerifyResult.Rejected(VerifyReason.WeakKey)
            }

            68 -> {
                return VerifyResult.Rejected(VerifyReason.WeakSignature)
            }

            22 -> {
                return VerifyResult.Rejected(VerifyReason.UnknownIssuer)
            }

            else -> {
                return VerifyResult.Rejected(VerifyReason.BadEncoding)
            }
        }
    }
    val verdict = Verification(this).verify(chain, reference, hiddenName = hiddenName)
    if (verdict is VerifyResult.Rejected) return verdict
    if (!chain[0].matchesHost(reference)) {
        return VerifyResult.Rejected(
            VerifyReason.HostnameMismatch(reference.value, runCatching { chain[0].dnsNames }.getOrDefault(emptyList())),
        )
    }
    return verdict
}
