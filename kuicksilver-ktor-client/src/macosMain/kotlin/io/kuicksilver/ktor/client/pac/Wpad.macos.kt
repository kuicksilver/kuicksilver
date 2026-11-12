// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client.pac

import kotlinx.cinterop.readBytes
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFRelease
import platform.Foundation.CFBridgingRelease
import platform.SystemConfiguration.DHCPInfoGetOptionData
import platform.SystemConfiguration.SCDynamicStoreCopyDHCPInfo
import platform.SystemConfiguration.SCDynamicStoreCopyValue
import platform.SystemConfiguration.SCDynamicStoreKeyCreateNetworkGlobalEntity
import platform.SystemConfiguration.kSCDynamicStoreDomainState
import platform.SystemConfiguration.kSCEntNetDNS

/** Option 252 of the primary service's DHCP lease (`SCDynamicStoreCopyDHCPInfo`, `DHCPInfoGetOptionData`). */
internal actual fun dhcpWpadUrl(): String? {
    val info = SCDynamicStoreCopyDHCPInfo(null, null) ?: return null
    try {
        val data = DHCPInfoGetOptionData(info, 252u) ?: return null
        val n = CFDataGetLength(data).toInt()
        if (n <= 0 || n > 2048) return null
        val bytes = CFDataGetBytePtr(data)?.readBytes(n) ?: return null
        return bytes
            .decodeToString()
            .trimEnd('\u0000')
            .trim()
            .takeIf { it.isNotEmpty() }
    } finally {
        CFRelease(info)
    }
}

/** `State:/Network/Global/DNS`: its DomainName, then its SearchDomains; then the host name's domain. */
internal actual fun dnsDomains(): List<String> {
    val out = ArrayList<String>()
    val key = SCDynamicStoreKeyCreateNetworkGlobalEntity(null, kSCDynamicStoreDomainState, kSCEntNetDNS)
    if (key != null) {
        try {
            val value = SCDynamicStoreCopyValue(null, key)
            val dict = value?.let { CFBridgingRelease(it) } as? Map<*, *>
            (dict?.get("DomainName") as? String)?.let { out += it }
            (dict?.get("SearchDomains") as? List<*>)?.forEach { (it as? String)?.let { d -> out += d } }
        } finally {
            CFRelease(key)
        }
    }
    hostNameDomain()?.let { out += it }
    return out.distinct()
}
