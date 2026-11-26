// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.util.logging.Logger
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.TlsVersions

/**
 * RFC 9113 section 9.2.2: "deployments of HTTP/2 that use TLS 1.2 MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 * \[TLS-ECDHE\] with the P-256 elliptic curve \[RFC8422\]". The TLS layer keeps it per handshake: a TLS 1.2 handshake
 * whose certificate has no rsaEncryption key or whose groups lack P-256 is not offered `h2` (`h2_allowed` in `ksl_ctx.c`),
 * so such a client gets HTTP/1.1, or `no_application_protocol` when it offers `h2` alone. Here, at the start: a connector
 * that serves HTTP/2 over TLS 1.2 without [KeyExchangeGroups.SECP256R1] among its groups is refused (no TLS 1.2 client
 * could get HTTP/2 from it, whatever its certificate), and one whose own certificate has no rsaEncryption key (an EC key,
 * or an RSA-PSS one, which serves that suite only to clients that offer the RSA-PSS signature schemes) is logged at Info,
 * since its TLS 1.2 clients get HTTP/1.1. Identities an `sniSelector` returns are not known before their handshakes: the
 * TLS layer decides for them.
 *
 * @throws IllegalArgumentException for HTTP/2 over TLS 1.2 without P-256.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
internal fun checkTls12H2(
    tls: KuicksilverTlsConnector,
    http2: Boolean,
    log: Logger,
) {
    if (!http2 || tls.versions != TlsVersions.Tls12And13) return
    require(KeyExchangeGroups.SECP256R1 in tls.tls.keyExchangeGroups.groups) {
        "HTTP/2 over TLS 1.2 on ${tls.host}:${tls.port} needs secp256r1 among tls { keyExchangeGroups } (RFC 9113 section " +
            "9.2.2: deployments of HTTP/2 that use TLS 1.2 MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 with the P-256 " +
            "curve): add it, set tls { versions = TlsVersions.Tls13 }, or http2 { enabled = false }"
    }
    val leaf = tls.identity?.chain?.firstOrNull() ?: return
    if (leaf.hasRsaKey() != false) return
    log.info(
        "TLS 1.2 on ${tls.host}:${tls.port}: the certificate has no rsaEncryption key, so TLS 1.2 clients get HTTP/1.1, not " +
            "HTTP/2 (RFC 9113 section 9.2.2 requires TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 of HTTP/2 over TLS 1.2); TLS 1.3 " +
            "clients get HTTP/2 (docs/guide/engine-tls.md, \"TLS 1.2 on the server\")",
    )
}

/** rsaEncryption, 1.2.840.113549.1.1.1 (RFC 8017 appendix A.1), as the DER content of its OBJECT IDENTIFIER. */
private val RSA_ENCRYPTION = byteArrayOf(0x2a, 0x86.toByte(), 0x48, 0x86.toByte(), 0xf7.toByte(), 0x0d, 0x01, 0x01, 0x01)

/**
 * Whether the certificate's subjectPublicKeyInfo algorithm is rsaEncryption (RFC 5280 section 4.1: tbsCertificate's
 * optional [0] version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo); null when the DER does
 * not have that shape.
 */
internal fun Certificate.hasRsaKey(): Boolean? {
    val b = der
    val cert = tlv(b, 0) ?: return null
    val tbs = tlv(b, cert.first) ?: return null
    var at = tbs.first // the first child of tbsCertificate
    if (at < tbs.second && b[at].toInt() and 0xff == 0xa0) at = tlv(b, at)?.second ?: return null // version
    repeat(5) { at = tlv(b, at)?.second ?: return null } // serial, signature, issuer, validity, subject
    val spki = tlv(b, at) ?: return null
    val algorithm = tlv(b, spki.first) ?: return null
    if (b[algorithm.first].toInt() != 0x06) return null // OBJECT IDENTIFIER
    val oid = tlv(b, algorithm.first) ?: return null
    return b.copyOfRange(oid.first, oid.second).contentEquals(RSA_ENCRYPTION)
}

/** The DER TLV at [at]: the start of its content and its end; null past the array or for a length form DER does not use. */
private fun tlv(
    b: ByteArray,
    at: Int,
): Pair<Int, Int>? {
    if (at + 2 > b.size) return null
    var p = at + 1
    val first = b[p++].toInt() and 0xff
    val len =
        if (first < 0x80) {
            first
        } else {
            val n = first and 0x7f
            if (n == 0 || n > 3 || p + n > b.size) return null
            var v = 0
            repeat(n) { v = (v shl 8) or (b[p++].toInt() and 0xff) }
            v
        }
    return if (p + len > b.size) null else p to p + len
}
