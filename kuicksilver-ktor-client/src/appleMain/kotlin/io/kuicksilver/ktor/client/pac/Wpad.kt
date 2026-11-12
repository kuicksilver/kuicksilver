// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

/**
 * WPAD discovery (draft-ietf-wrec-wpad-01) without walking up the DNS tree: the PAC URL of DHCP option 252 when the
 * platform gives it (`http` or `https` only, never `file`), then `http://wpad.<domain>/wpad.dat` for each configured DNS
 * search domain exactly as configured (no parent domain is tried, so no `wpad.<public suffix>` such as `wpad.co.uk`),
 * then `http://wpad/wpad.dat`, a single-label name the system resolver completes with its own search domains (no
 * "devolution" up the tree). `.local` (mDNS) domains and single-label domains are skipped.
 */
internal fun wpadCandidates(
    dhcpUrl: String?,
    searchDomains: List<String>,
): List<String> {
    val out = LinkedHashSet<String>()
    dhcpUrl
        ?.trim()
        ?.trimEnd('\u0000')
        ?.trim()
        ?.takeIf { it.startsWith("http://", ignoreCase = true) || it.startsWith("https://", ignoreCase = true) }
        ?.let { out += it }
    for (raw in searchDomains) {
        val domain = raw.trim().trimEnd('.').lowercase()
        if (domain.isEmpty() || '.' !in domain || domain.endsWith(".local") || domain.any { it == '/' || it == '@' || it == ':' }) continue
        out += "http://wpad.$domain/wpad.dat"
    }
    out += "http://wpad/wpad.dat"
    return out.toList()
}

/** The PAC URL of DHCP option 252, where the platform gives it (macOS: `SCDynamicStoreCopyDHCPInfo`); null otherwise. */
internal expect fun dhcpWpadUrl(): String?

/** The configured DNS search domains, where the platform gives them (macOS: the system's DNS configuration). */
internal expect fun dnsSearchDomains(): List<String>
