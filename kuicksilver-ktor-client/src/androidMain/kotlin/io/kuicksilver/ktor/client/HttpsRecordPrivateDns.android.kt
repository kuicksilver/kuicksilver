// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import android.net.ConnectivityManager
import android.os.Build
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * The system resolver (`DnsResolver.rawQuery`, API 29 and up), treated as cryptographically protected while the default
 * network uses Android's strict Private DNS mode: DNS over TLS to a configured server
 * (`LinkProperties.getPrivateDnsServerName()` non-null and `isPrivateDnsActive`), which cannot fall back to plain DNS.
 * Then a failed HTTPS record lookup abandons the request (RFC 9460 section 3.1). The opportunistic mode ("Automatic")
 * may fall back to plain DNS when DNS over TLS is blocked, so it counts as unprotected, as does any network below API 28.
 * The engine also takes the network's NAT64 prefix from [connectivity] (`LinkProperties.getNat64Prefix`, API 30), for
 * Happy Eyeballs on an IPv6-only network without 464XLAT (docs/guide/ktor.md, "Happy Eyeballs").
 */
@ExperimentalKuicksilverApi
public fun HttpsRecordSource.Companion.followingPrivateDns(connectivity: ConnectivityManager): HttpsRecordSource {
    AndroidConnectivity.manager = connectivity // also where the network's NAT64 prefix comes from (platformNat64Prefixes)
    return HttpsRecordSource.ProtectedSystem {
        if (Build.VERSION.SDK_INT < 28) {
            false
        } else {
            val lp = connectivity.getLinkProperties(connectivity.activeNetwork)
            lp != null && lp.isPrivateDnsActive && lp.privateDnsServerName != null
        }
    }
}
