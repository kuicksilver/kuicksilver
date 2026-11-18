// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.io.IOException

/**
 * Whether the platform's network security policy lets the engine talk to [host] in cleartext (`http://`, `ws://`). On
 * Android this is the app's Network Security Configuration (`NetworkSecurityPolicy.isCleartextTrafficPermitted`, which
 * is false by default from targetSdk 28), as OkHttp, HttpURLConnection and Cronet honour it; elsewhere always true.
 */
internal expect fun platformCleartextPermitted(host: String): Boolean

/** The refusal of a cleartext request, worded as OkHttp's (an IOException, as any connection failure). */
internal fun cleartextNotPermitted(host: String): kotlinx.io.IOException =
    kotlinx.io.IOException("CLEARTEXT communication to $host not permitted by network security policy")

/**
 * The host a cleartext request to [urlHost] is checked under, and named in its refusal: the address the connection goes
 * to, in one spelling per address, since the policy matches strings (lower case, one trailing dot dropped) and a rule for
 * an address must not be passed by another spelling of it.
 * - An IPv6 literal, without its brackets, in the text RFC 5952 recommends (section 4: lower-case hex, no leading zeros,
 *   the longest run of two or more zero groups as `::`, the first of equal runs). Its zone (`fe80::1%wlan0`, RFC 6874)
 *   is dropped: the policy knows addresses and names, not interfaces, so a rule for `fe80::1` holds for that address on
 *   every link (and a rule written with a zone matches nothing).
 * - An IPv4-mapped IPv6 literal (`::ffff:0:0/96`, RFC 4291 section 2.5.5.2) as the dotted quad of its last four bytes:
 *   the connection goes to that IPv4 address ([RequestDns] connects it so, as the JDK and Android do), so a rule for
 *   `192.0.2.1` holds for `[::ffff:192.0.2.1]` too.
 * - A host with the form of an IPv4 literal other than a dotted quad, as the dotted quad it names (`127.1` is
 *   `127.0.0.1`).
 * - A name, as it is.
 *
 * Fails with an [IOException] before the policy is asked, whatever it says, for a host no connection can be made to
 * under it: an IP literal (brackets or a colon) that is no IPv6 address; a numeric host that platforms read differently
 * (`010.0.0.1`, the failure of its lookup, [numericAnswer]); a host beginning with a dot (Android's policy throws on
 * one); and a name with non-ASCII characters. The engine does not map an internationalised name to its A-label (UTS 46,
 * as browsers and OkHttp do): the policy would be asked about the Unicode text while the rules name A-labels, so such a
 * name is refused here and the URL must carry the A-label (`xn--...`, RFC 5890 section 2.3.2.1), as DNS and SNI need
 * (`DnsMessage.isAskable`, the TLS module's `HostName`).
 */
@OptIn(InternalKuicksilverApi::class) // TcpAddress.hostText
internal fun cleartextPolicyHost(urlHost: String): String {
    val host = socketHost(urlHost)
    if (host.any { it.code >= 0x80 }) {
        throw IOException(
            "$host is not an ASCII host name: the engine does not convert internationalised names; use its A-label (xn--...)",
        )
    }
    if (host.startsWith('.')) throw IOException("$host is not a host name: it begins with a dot")
    if (':' in host || urlHost.startsWith('[')) {
        // parseIpLiteral drops the zone; scope 0 leaves it out of the text
        val ip = parseIpLiteral(host)?.takeIf { it.size == 16 } ?: throw IOException("$urlHost is not an IP address")
        val mapped = (0 until 10).all { ip[it].toInt() == 0 } && ip[10] == 0xff.toByte() && ip[11] == 0xff.toByte()
        return TcpAddress(if (mapped) ip.copyOfRange(12, 16) else ip, 0).hostText
    }
    return numericAnswer(host, ipv6 = false)?.single()?.hostText ?: host
}
