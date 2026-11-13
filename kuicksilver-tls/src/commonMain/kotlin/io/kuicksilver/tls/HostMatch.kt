// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * Whether this certificate's subjectAltName names [host] (RFC 9525 section 6.3), the name check a client makes before it
 * attributes authority for [host] to a server presenting it (RFC 9110 section 4.3.4); trust in the chain is not looked at.
 *
 * An IP literal (IP-ID) matches an iPAddress entry of the same bytes; an IPv4 literal written with leading zeros
 * (`127.000.000.001`) is a reg-name in RFC 3986 section 3.2.2, not the address, and matches nothing. A DNS name (DNS-ID) matches a dNSName entry equal to it
 * after ASCII lower-casing and removal of one trailing dot, or a wildcard entry whose left-most label is `*` alone and which
 * has at least two more labels (`*.example.com`): the `*` stands for exactly one non-empty label. Partial wildcards
 * (`f*.example.com`) and wildcards anywhere else never match, as with OpenSSL's `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`, which
 * the client verifier uses. The subject common name is never used (RFC 9110 section 4.3.4: no CN-ID). A certificate whose
 * names cannot be read matches nothing.
 */
@ExperimentalKuicksilverApi
public fun Certificate.matchesHost(host: HostName): Boolean {
    val (dns, ips) =
        try {
            dnsNames to ipAddresses
        } catch (_: TlsException) {
            return false
        }
    if (host.isIpLiteral) {
        val bytes = ipLiteralBytes(host.value) ?: return false
        return ips.any { it.contentEquals(bytes) }
    }
    val name = host.value
    return dns.any { presented ->
        val p = presented.lowercase().let { if (it.length > 1 && it.endsWith('.')) it.dropLast(1) else it }
        when {
            '*' !in p -> {
                p == name
            }

            p.startsWith("*.") && '*' !in p.substring(2) && p.substring(2).contains('.') -> {
                val dot = name.indexOf('.')
                dot > 0 && name.substring(dot + 1) == p.substring(2)
            }

            else -> {
                false
            }
        }
    }
}

/**
 * The bytes of a normalized IPv4 (4) or IPv6 (16, RFC 4291 section 2.2) literal, or null. An IPv4 part is a `dec-octet`
 * of RFC 3986 section 3.2.2, without leading zeros: `127.000.000.001` is a reg-name there, not the address.
 */
private fun ipLiteralBytes(s: String): ByteArray? {
    if (':' !in s) {
        val parts = s.split('.')
        if (parts.size != 4) return null
        return ByteArray(4) { i ->
            (
                parts[i]
                    .takeIf { it.length in 1..3 && it.all(Char::isDigit) && (it.length == 1 || it[0] != '0') }
                    ?.toInt()
                    ?.takeIf { it <= 255 } ?: return null
            ).toByte()
        }
    }
    val doubleColon = s.indexOf("::")
    if (doubleColon >= 0 && s.indexOf("::", doubleColon + 1) >= 0) return null

    fun groups(part: String): List<String> = if (part.isEmpty()) emptyList() else part.split(':')
    val head = groups(if (doubleColon >= 0) s.substring(0, doubleColon) else s)
    val tail = if (doubleColon >= 0) groups(s.substring(doubleColon + 2)) else emptyList()

    fun words(gs: List<String>): List<Int>? =
        gs.withIndex().flatMap { (i, g) ->
            if ('.' in g) {
                if (i != gs.lastIndex) return null
                val v4 = ipLiteralBytes(g)?.takeIf { it.size == 4 } ?: return null
                listOf(
                    ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff),
                    ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff),
                )
            } else {
                if (g.length !in 1..4) return null
                listOf(g.toIntOrNull(16) ?: return null)
            }
        }
    val h = words(head) ?: return null
    val t = words(tail) ?: return null
    val zeros = 8 - h.size - t.size
    if ((doubleColon < 0 && zeros != 0) || (doubleColon >= 0 && zeros < 1)) return null
    val all = h + List(if (doubleColon >= 0) zeros else 0) { 0 } + t
    return ByteArray(16) { i -> (all[i / 2] shr (if (i % 2 == 0) 8 else 0)).toByte() }
}
