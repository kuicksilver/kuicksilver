// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.kuicksilver.annotations.InternalKuicksilverApi

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
 * The host a cleartext request to [urlHost] is checked under, the address the connection goes to as the policy knows it: an IPv6
 * literal without its brackets, and a host with the form of an IPv4 literal other than a dotted quad as the dotted quad it names
 * (`127.1` is `127.0.0.1`), since the policy matches strings and a rule for an address must not be passed by another spelling of
 * it. A numeric host that platforms read differently (`010.0.0.1`) fails here with the failure of its lookup ([numericAnswer]),
 * before the policy is asked: it is no host at all, whatever the policy says.
 */
@OptIn(InternalKuicksilverApi::class) // TcpAddress.hostText
internal fun cleartextPolicyHost(urlHost: String): String {
    val host = urlHost.removePrefix("[").removeSuffix("]")
    return numericAnswer(host, ipv6 = false)?.single()?.hostText ?: host
}
