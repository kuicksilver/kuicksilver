// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

/** iOS has no public API for the DHCP options a network gave. */
internal actual fun dhcpWpadUrl(): String? = null

/**
 * None: iOS's public SDK has libresolv's `res_ninit` (whose state lists the search domains), but Kotlin/Native ships no
 * binding for it; WPAD there tries `http://wpad/wpad.dat`, which the system resolver completes with its search domains.
 */
internal actual fun dnsSearchDomains(): List<String> = emptyList()
