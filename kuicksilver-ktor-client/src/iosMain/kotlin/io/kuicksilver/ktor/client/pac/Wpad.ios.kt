// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.pac

/** iOS has no public API for the DHCP options a network gave. */
internal actual fun dhcpWpadUrl(): String? = null

/** iOS has no public API for the DNS search domains: the host name's domain only. */
internal actual fun dnsDomains(): List<String> = listOfNotNull(hostNameDomain())
