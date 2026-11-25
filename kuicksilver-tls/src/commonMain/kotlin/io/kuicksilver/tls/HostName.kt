// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

/** The server_name a client sends: its normalized [TlsConfig.serverName], never an IP literal (RFC 6066 section 3), whatever the reference identifier is. */
internal fun sniOf(config: TlsConfig): String? =
    config.serverName
        ?.let { HostName.normalize(it) }
        ?.takeIf { !it.isIpLiteral }
        ?.value

/**
 * A reference identifier (RFC 9525): a DNS-ID or an IP-ID. Normalization: ASCII lower case, one trailing dot removed,
 * brackets around IPv6 literals removed. Non-ASCII names are rejected; convert IDNs to A-labels before calling.
 *
 * An IP literal is an IPv4 dotted quad of decimal octets without leading zeros or an IPv6 address (RFC 4291 section
 * 2.2), without a zone ID; anything else is a DNS name of LDH labels (RFC 1123 section 2.1, RFC 5890 section 2.3.1:
 * letters, digits and hyphens, no hyphen first or last), 1 to 63 octets each and at most 253 in all (RFC 1035 section
 * 2.3.4), whose last label is not all digits nor `0x` with hex digits (RFC 3696 section 2: no top-level domain is; the
 * WHATWG URL standard reads such a name as an IPv4 address, so `010.0.0.1`, `1.2.3` or `a.0x1f` is a malformed IPv4 literal,
 * not a name). Only SP and HTAB around [normalize]'s input are dropped. The same parser decides an IP-ID's address when a certificate is matched.
 *
 * @property value the normalized form; two names are equal when their values are.
 * @property isIpLiteral true for an IPv4 or IPv6 literal, which is matched against iPAddress entries of the certificate
 *   (IP-ID) and never sent as SNI (RFC 6066 section 3); false for a DNS name.
 */
public class HostName private constructor(
    public val value: String,
    public val isIpLiteral: Boolean,
) {
    /** Equal when the normalized names are. */
    override fun equals(other: Any?): Boolean = other is HostName && other.value == value

    /** Consistent with [equals]. */
    override fun hashCode(): Int = value.hashCode()

    /** The normalized name. */
    override fun toString(): String = value

    /** Holds [normalize], the only way to make a [HostName]. */
    public companion object {
        /**
         * Normalizes [input] as described on [HostName]. Throws [TlsException.Config] for an empty, non-ASCII or malformed
         * name (an IP literal with a leading zero or a zone ID, a label that is empty, longer than 63 octets or not LDH, a
         * name longer than 253 octets, an all-digit last label) and for a wildcard, which a reference identifier never
         * contains (RFC 9525).
         */
        public fun normalize(input: String): HostName {
            // OWS only (RFC 9110 section 5.6.3): a Unicode space is not whitespace around a name, it is a character of it
            var s = input.trim(' ', '\t')
            if (s.isEmpty()) throw TlsException.Config("empty host name")
            if (s.any { it.code >= 0x80 }) throw TlsException.Config("non-ASCII host name '$input': pass an A-label (punycode)")
            // brackets enclose an IPv6 literal only (RFC 3986 section 3.2.2: IP-literal = "[" IPv6address / IPvFuture "]")
            val bracketed = s.startsWith("[") && s.endsWith("]")
            if (bracketed) s = s.substring(1, s.length - 1)
            if (bracketed && ':' !in s) throw TlsException.Config("invalid host name '$input': brackets enclose an IPv6 literal only")
            if (s.endsWith(".") && s.length > 1) s = s.dropLast(1)
            s = s.lowercase()
            if (ipLiteralBytes(s) != null) return HostName(s, true)
            if (s.contains('*')) throw TlsException.Config("wildcards are not allowed in a reference identifier")
            if (!isLdhName(s)) throw TlsException.Config("invalid host name '$input'")
            return HostName(s, false)
        }

        /** LDH labels of 1 to 63 octets, at most 253 octets in all, the last label not all digits (see [HostName]). */
        private fun isLdhName(s: String): Boolean {
            if (s.length > 253) return false
            val labels = s.split('.')
            for (label in labels) {
                if (label.isEmpty() || label.length > 63 || label.first() == '-' || label.last() == '-') return false
                if (!label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' }) return false
            }
            // the WHATWG URL standard's "ends in a number": all digits, or "0x" and hex digits (an empty "0x" included)
            val last = labels.last()
            if (last.all { it in '0'..'9' }) return false
            return !(last.startsWith("0x") && last.drop(2).all { it in '0'..'9' || it in 'a'..'f' })
        }
    }
}
