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
 * @property value the normalized form; two names are equal when their values are.
 * @property isIpLiteral true for an IPv4 or IPv6 literal, which is matched against iPAddress entries of the certificate
 *   (IP-ID) and never sent as SNI (RFC 6066 section 3); false for a DNS name.
 */
public class HostName private constructor(
    public val value: String,
    public val isIpLiteral: Boolean,
) {
    override fun equals(other: Any?): Boolean = other is HostName && other.value == value

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value

    /** Holds [normalize], the only way to make a [HostName]. */
    public companion object {
        /**
         * Normalizes [input] as described on [HostName]. Throws [TlsException.Config] for an empty, non-ASCII or malformed
         * name and for a wildcard, which a reference identifier never contains (RFC 9525).
         */
        public fun normalize(input: String): HostName {
            var s = input.trim()
            if (s.isEmpty()) throw TlsException.Config("empty host name")
            if (s.any { it.code >= 0x80 }) throw TlsException.Config("non-ASCII host name '$input': pass an A-label (punycode)")
            if (s.startsWith("[") && s.endsWith("]")) s = s.substring(1, s.length - 1)
            if (s.endsWith(".") && s.length > 1) s = s.dropLast(1)
            s = s.lowercase()
            val ip = isIpv4(s) || isIpv6(s)
            if (!ip) {
                if (s.any { it != '.' && it != '-' && it !in 'a'..'z' && it !in '0'..'9' } || s.startsWith(".") ||
                    s.contains("..")
                ) {
                    throw TlsException.Config("invalid host name '$input'")
                }
                if (s.contains('*')) throw TlsException.Config("wildcards are not allowed in a reference identifier")
            }
            return HostName(s, ip)
        }

        private fun isIpv4(s: String): Boolean {
            val p = s.split('.')
            return p.size == 4 &&
                p.all { it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) && it.toInt() <= 255 }
        }

        private fun isIpv6(s: String): Boolean =
            s.contains(':') && s.all { it == ':' || it == '.' || it in '0'..'9' || it in 'a'..'f' } && s.count { it == ':' } in 2..7
    }
}
