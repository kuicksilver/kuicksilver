// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client.pac

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.toKString
import platform.posix.gethostname

/**
 * WPAD discovery (draft-ietf-wrec-wpad-01): the PAC URL of DHCP option 252 when the platform gives it, then
 * `http://wpad.<domain>/wpad.dat` for the host's DNS domains, from the most specific one up to the domain that still has
 * two labels: `a.corp.example.com` gives `wpad.a.corp.example.com`, `wpad.corp.example.com`, `wpad.example.com`, never
 * `wpad.com` (anyone could register `wpad.<public suffix>`; the walk stops at two labels, as Windows and Chromium do).
 * `.local` (mDNS) domains are skipped.
 */
internal fun wpadCandidates(
    dhcpUrl: String?,
    domains: List<String>,
): List<String> {
    val out = LinkedHashSet<String>()
    dhcpUrl
        ?.trim()
        ?.trimEnd('\u0000')
        ?.takeIf { it.isNotEmpty() }
        ?.let { out += it }
    for (raw in domains) {
        val labels =
            raw
                .trim()
                .trimEnd('.')
                .lowercase()
                .split('.')
                .filter { it.isNotEmpty() }
        if (labels.isEmpty() || labels.last() == "local") continue
        for (i in 0..labels.size - 2) out += "http://wpad.${labels.drop(i).joinToString(".")}/wpad.dat"
    }
    return out.toList()
}

/** The PAC URL of DHCP option 252, where the platform gives it (macOS: `SCDynamicStoreCopyDHCPInfo`); null otherwise. */
internal expect fun dhcpWpadUrl(): String?

/** The host's DNS domains (macOS: the DNS search domains and domain name of the system's configuration), its own first. */
internal expect fun dnsDomains(): List<String>

/** The host name's domain: what follows its first label, when the name has one. */
internal fun hostNameDomain(): String? =
    memScoped {
        val buf = allocArray<ByteVar>(256)
        if (gethostname(buf, 256u) != 0) return null
        buf.toKString().substringAfter('.', "").takeIf { it.isNotEmpty() }
    }
