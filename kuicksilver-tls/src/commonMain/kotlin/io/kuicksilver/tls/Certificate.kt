// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.tls

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.Ksl

/**
 * An X.509 certificate in DER form with the few fields the TLS layer needs; parsing is lazy and failures surface as [TlsException.Config].
 * A validity time the minimal walker cannot read (OpenSSL also accepts a fractional GeneralizedTime or a UTCTime offset) fails only
 * the validity bounds, never the names.
 */
public class Certificate(
    der: ByteArray,
) {
    /** The DER bytes, copied on construction and never handed out: equality, the pins and the native layer use them. */
    internal val encoded: ByteArray = der.copyOf()

    /** The DER encoding (RFC 5280); a fresh copy on every read, so changing it changes nothing here. */
    public val der: ByteArray get() = encoded.copyOf()

    /** SHA-256 over the DER SubjectPublicKeyInfo: the value pins are compared against (RFC 7469). */
    public val spkiSha256: SpkiSha256 by lazy { SpkiSha256(Ksl.spkiSha256(encoded)) }

    private val parsed: Der.CertificateFields by lazy { Der.parseCertificate(encoded) }

    /** dNSName entries of the subjectAltName extension, as presented (case preserved). */
    public val dnsNames: List<String> get() = parsed.dnsNames

    /** iPAddress entries of the subjectAltName extension, as 4- or 16-byte arrays. */
    public val ipAddresses: List<ByteArray> get() = parsed.ipAddresses

    /** Validity bounds as Unix epoch seconds. */
    public val notBeforeEpochSeconds: Long get() = parsed.notBefore ?: Der.fail()

    /**
     * End of the validity period (notAfter, RFC 5280 section 4.1.2.5) as Unix epoch seconds; [TlsException.Config] when the
     * time is in a form the walker cannot read. Informational: the handshake checks validity in the verifier, not here.
     */
    public val notAfterEpochSeconds: Long get() = parsed.notAfter ?: Der.fail()

    override fun equals(other: Any?): Boolean = other is Certificate && other.encoded.contentEquals(encoded)

    override fun hashCode(): Int = encoded.contentHashCode()

    /** Never throws: diagnostics of a certificate the walker cannot read show no names. */
    override fun toString(): String =
        "Certificate(dns=${runCatching { dnsNames }.getOrDefault(
            emptyList(),
        )}, spki=${runCatching { spkiSha256.toString() }.getOrDefault("?")})"

    /** Holds [parsePem]. */
    public companion object {
        /**
         * Every `CERTIFICATE` block of [pem] in order (a CA bundle, a chain file); blocks of other types and text between
         * blocks are skipped. Each block is parsed now, so a damaged file fails here with [TlsException.Config], as does a
         * text without any certificate.
         */
        public fun parsePem(pem: String): List<Certificate> {
            val blocks =
                try {
                    Pem.blocks(pem, "CERTIFICATE")
                } catch (
                    e: IllegalArgumentException,
                ) {
                    throw TlsException.Config("malformed PEM: ${e.message}")
                }
            if (blocks.isEmpty()) throw TlsException.Config("no CERTIFICATE block in PEM")
            return blocks.map { der ->
                // the minimal DER walker reports structural damage as Config, but truncated field lists surface as index errors
                try {
                    Certificate(der).also {
                        it.dnsNames
                        it.notBeforeEpochSeconds
                        it.notAfterEpochSeconds
                    }
                } catch (
                    e: TlsException,
                ) {
                    throw e
                } catch (e: RuntimeException) {
                    throw TlsException.Config("malformed certificate DER")
                }
            }
        }
    }
}

/** Minimal DER walker: enough for validity and subjectAltName. Not a general-purpose parser. */
internal object Der {
    class CertificateFields(
        val notBefore: Long?,
        val notAfter: Long?,
        val dnsNames: List<String>,
        val ipAddresses: List<ByteArray>,
    ) // null: a time this walker cannot read

    private class Tlv(
        val tag: Int,
        val start: Int,
        val end: Int,
    ) // content bounds

    private fun tlv(
        b: ByteArray,
        at: Int,
        limit: Int,
    ): Tlv {
        if (at + 2 > limit) fail()
        val tag = b[at].toInt() and 0xff
        var i = at + 1
        var len = b[i++].toInt() and 0xff
        if (len and 0x80 !=
            0
        ) {
            val n =
                len and 0x7f
            if (n == 0 || n > 4 ||
                i + n > limit
            ) {
                fail()
            }
            len = 0
            repeat(n) { len = (len shl 8) or (b[i++].toInt() and 0xff) }
        }
        if (i + len > limit) fail()
        return Tlv(tag, i, i + len)
    }

    private fun children(
        b: ByteArray,
        t: Tlv,
    ): List<Tlv> {
        val out = ArrayList<Tlv>()
        var at = t.start
        while (at <
            t.end
        ) {
            val c = tlv(b, at, t.end)
            out += c
            at = c.end
        }
        return out
    }

    fun fail(): Nothing = throw TlsException.Config("malformed certificate DER")

    fun parseCertificate(b: ByteArray): CertificateFields {
        val cert = tlv(b, 0, b.size)
        if (cert.tag != 0x30) fail()
        val tbs = tlv(b, cert.start, cert.end)
        if (tbs.tag != 0x30) fail()
        val fields = children(b, tbs)
        var i = 0
        if (fields[i].tag == 0xa0) i++ // version
        i++ // serial
        i++ // signature algorithm
        i++ // issuer
        val validity = children(b, fields[i++])
        if (validity.size != 2) fail()
        val notBefore = timeOrNull(b, validity[0])
        val notAfter = timeOrNull(b, validity[1])
        i++ // subject
        i++ // subjectPublicKeyInfo
        val dns = ArrayList<String>()
        val ips = ArrayList<ByteArray>()
        val ext = fields.drop(i).firstOrNull { it.tag == 0xa3 }
        if (ext != null) {
            for (e in children(b, tlv(b, ext.start, ext.end))) {
                val parts = children(b, e)
                val oid = parts[0]
                if (oid.tag == 0x06 && oid.end - oid.start == 3 && b[oid.start] == 0x55.toByte() && b[oid.start + 1] == 0x1d.toByte() &&
                    b[oid.start + 2] == 0x11.toByte()
                ) {
                    val value = parts.last()
                    if (value.tag != 0x04) fail()
                    for (name in children(b, tlv(b, value.start, value.end))) {
                        when (name.tag) {
                            0x82 -> dns += b.decodeToString(name.start, name.end)
                            0x87 -> ips += b.copyOfRange(name.start, name.end)
                        }
                    }
                }
            }
        }
        return CertificateFields(notBefore, notAfter, dns, ips)
    }

    private fun timeOrNull(
        b: ByteArray,
        t: Tlv,
    ): Long? =
        try {
            time(b, t)
        } catch (_: TlsException.Config) {
            null
        } catch (_: RuntimeException) {
            null
        }

    private fun time(
        b: ByteArray,
        t: Tlv,
    ): Long {
        val s = b.decodeToString(t.start, t.end)
        if (!s.endsWith("Z")) fail()
        val digits = s.dropLast(1)
        if (digits.any { it !in '0'..'9' }) fail()
        val (y, rest) =
            when (t.tag) {
                0x17 -> {
                    val yy = digits.substring(0, 2).toInt()
                    (if (yy >= 50) 1900 + yy else 2000 + yy) to digits.substring(2)
                }

                // UTCTime, RFC 5280 4.1.2.5.1
                0x18 -> {
                    digits.substring(0, 4).toInt() to digits.substring(4)
                }

                else -> {
                    fail()
                }
            }
        if (rest.length < 10) fail()
        val mo = rest.substring(0, 2).toInt()
        val d = rest.substring(2, 4).toInt()
        val h = rest.substring(4, 6).toInt()
        val mi = rest.substring(6, 8).toInt()
        val sec = rest.substring(8, 10).toInt()
        return epochSeconds(y, mo, d, h, mi, sec)
    }

    /** Days-from-civil (Howard Hinnant), valid for the proleptic Gregorian calendar. */
    private fun epochSeconds(
        y0: Int,
        m: Int,
        d: Int,
        h: Int,
        mi: Int,
        s: Int,
    ): Long {
        val y = if (m <= 2) y0 - 1 else y0
        val era = (if (y >= 0) y else y - 399) / 400
        val yoe = y - era * 400
        val doy = (153 * (m + (if (m > 2) -3 else 9)) + 2) / 5 + d - 1
        val doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        val days = era.toLong() * 146097 + doe - 719468
        return days * 86400 + h * 3600L + mi * 60 + s
    }
}
