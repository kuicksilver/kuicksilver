// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.ktor.network.TcpAddress

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
 * The host a cleartext request to [urlHost] is checked under: the address the connection goes to, in one spelling per
 * address, since the policy matches strings and a rule for an address must not be passed by another spelling of it.
 * - An IPv6 literal, without its brackets, in the text RFC 5952 recommends (section 4: lower-case hex, no leading zeros,
 *   the longest run of two or more zero groups as `::`, the first of equal runs); an IPv4-mapped address as
 *   `::ffff:` and its dotted quad (section 5). Its zone (`fe80::1%wlan0`, RFC 6874) is dropped: the policy knows
 *   addresses and names, not interfaces, so a rule for `fe80::1` holds for that address on every link. A literal that
 *   does not parse is asked about as written, lower case and without its zone; its connection fails anyway.
 * - A host with the form of an IPv4 literal other than a dotted quad, as the dotted quad it names (`127.1` is
 *   `127.0.0.1`). One that platforms read differently (`010.0.0.1`) fails here with the failure of its lookup
 *   ([numericAnswer]), before the policy is asked: it is no host at all, whatever the policy says.
 * - A name, as it is.
 */
@OptIn(InternalKuicksilverApi::class) // TcpAddress.hostText
internal fun cleartextPolicyHost(urlHost: String): String {
    val host = socketHost(urlHost)
    if (':' in host) {
        // parseIpLiteral drops the zone; scope 0 leaves it out of the text
        val ip = parseIpLiteral(host) ?: return host.substringBefore('%').lowercase()
        return TcpAddress(ip, 0).hostText
    }
    return numericAnswer(host, ipv6 = false)?.single()?.hostText ?: host
}
