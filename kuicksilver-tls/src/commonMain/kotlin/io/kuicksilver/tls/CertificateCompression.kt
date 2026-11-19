// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslLoader

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

    public companion object {
        /**
         * The algorithms this platform's native library compresses certificates with (`KSL_GET_CERT_COMPRESSORS`): zlib and
         * brotli, but zlib alone on Android and iOS, whose library has brotli's decoder only (ADR-0025). Every platform
         * decompresses both. There a server sends its chain in zlib and a client its certificate uncompressed.
         */
        @InternalKuicksilverApi
        public fun compressors(): Set<CertificateCompression> {
            KslLoader.ensureLoaded()
            val ctx = Ksl.ctxNew(KslConst.CLIENT)
            try {
                val ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
                try {
                    val bits = Ksl.sslGet(ssl, KslConst.GET_CERT_COMPRESSORS).firstOrNull()?.toInt() ?: 0
                    return entries.filterTo(LinkedHashSet()) { bits and (1 shl (it.codePoint - 1)) != 0 }
                } finally {
                    Ksl.sslFree(ssl)
                }
            } finally {
                Ksl.ctxFree(ctx)
            }
        }

        /** The algorithm of a `KSL_GET_CERT_COMPRESSION` answer (2 bytes big-endian), null for 0 (a plain Certificate) or a short answer. */
        internal fun of(getter: ByteArray): CertificateCompression? {
            if (getter.size < 2) return null
            val code = (getter[0].toInt() and 0xff shl 8) or (getter[1].toInt() and 0xff)
            return entries.firstOrNull { it.codePoint == code }
        }
    }
}
