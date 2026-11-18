// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * An algorithm of TLS certificate compression (RFC 8879, the "TLS Certificate Compression Algorithm IDs" registry): what the
 * peer's certificate chain came compressed with ([TlsConnection.peerCertificateCompression], and `peerCertificateCompression`
 * of a QUIC connection). See [TlsConfig.Builder.certificateCompression].
 *
 * @property codePoint the algorithm's IANA code point.
 */
@ExperimentalKuicksilverApi
public enum class CertificateCompression(
    public val codePoint: Int,
) {
    /** zlib (RFC 1950), code point 1. */
    Zlib(1),

    /** brotli (RFC 7932), code point 2: offered first. */
    Brotli(2),
    ;

    internal companion object {
        /** The algorithm of a `KSL_GET_CERT_COMPRESSION` answer (2 bytes big-endian), null for 0 (a plain Certificate) or a short answer. */
        fun of(getter: ByteArray): CertificateCompression? {
            if (getter.size < 2) return null
            val code = (getter[0].toInt() and 0xff shl 8) or (getter[1].toInt() and 0xff)
            return entries.firstOrNull { it.codePoint == code }
        }
    }
}
