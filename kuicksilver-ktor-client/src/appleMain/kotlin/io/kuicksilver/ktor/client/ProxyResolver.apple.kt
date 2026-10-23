// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import io.ktor.http.isSecure
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.CFNetwork.CFNetworkCopyProxiesForURL
import platform.CFNetwork.CFNetworkCopySystemProxySettings
import platform.CFNetwork.kCFProxyHostNameKey
import platform.CFNetwork.kCFProxyPortNumberKey
import platform.CFNetwork.kCFProxyTypeAutoConfigurationJavaScript
import platform.CFNetwork.kCFProxyTypeAutoConfigurationURL
import platform.CFNetwork.kCFProxyTypeHTTP
import platform.CFNetwork.kCFProxyTypeHTTPS
import platform.CFNetwork.kCFProxyTypeKey
import platform.CFNetwork.kCFProxyTypeNone
import platform.CFNetwork.kCFProxyTypeSOCKS
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFURLRef
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSNumber
import platform.Foundation.NSURL

internal actual val platformSystemProxyResolver: ProxyResolver = AppleSystemProxyResolver

/**
 * The system's proxy settings (`CFNetworkCopySystemProxySettings`) applied to the URL by `CFNetworkCopyProxiesForURL`,
 * which honours the exceptions list and "exclude simple host names". A PAC entry is not run (a direct connection and a
 * warning). The calls run on [Dispatchers.IO].
 */
internal object AppleSystemProxyResolver : WarningProxyResolver {
    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
    ): ResolvedProxy? {
        val host = socketHost(url.host)
        if (isLoopback(host)) return null
        val target = "${if (url.protocol.isSecure()) "https" else "http"}://${uriHost(host)}:${url.port}/"
        return pickCfProxy(withContext(Dispatchers.IO) { systemProxies(target) }, warn)
    }
}

/** What CFNetwork says for [urlString], in its order. */
internal fun systemProxies(urlString: String): List<CfProxy> {
    val settings = CFNetworkCopySystemProxySettings() ?: return emptyList()
    try {
        val nsUrl = NSURL.URLWithString(urlString) ?: return emptyList()

        @Suppress("UNCHECKED_CAST")
        val cfUrl = CFBridgingRetain(nsUrl) as CFURLRef
        try {
            val proxies = CFNetworkCopyProxiesForURL(cfUrl, settings) ?: return emptyList()
            return cfProxiesFrom(CFBridgingRelease(proxies) as? List<*> ?: return emptyList())
        } finally {
            CFRelease(cfUrl)
        }
    } finally {
        CFRelease(settings)
    }
}

private fun CFStringRef?.text(): String = CFBridgingRelease(CFRetain(this)) as String

/** The proxy dictionaries of a `CFNetworkCopyProxiesForURL` answer as [CfProxy] entries. */
internal fun cfProxiesFrom(list: List<*>): List<CfProxy> {
    val typeKey = kCFProxyTypeKey.text()
    val hostKey = kCFProxyHostNameKey.text()
    val portKey = kCFProxyPortNumberKey.text()
    val types =
        mapOf(
            kCFProxyTypeNone.text() to CfProxy.Type.None,
            kCFProxyTypeHTTP.text() to CfProxy.Type.Http,
            kCFProxyTypeHTTPS.text() to CfProxy.Type.Https,
            kCFProxyTypeSOCKS.text() to CfProxy.Type.Socks,
            kCFProxyTypeAutoConfigurationURL.text() to CfProxy.Type.AutoConfiguration,
            kCFProxyTypeAutoConfigurationJavaScript.text() to CfProxy.Type.AutoConfiguration,
        )
    return list.mapNotNull { entry ->
        val d = entry as? Map<*, *> ?: return@mapNotNull null
        val port = d[portKey].let { (it as? Number)?.toInt() ?: (it as? NSNumber)?.intValue }
        CfProxy(types[d[typeKey] as? String] ?: CfProxy.Type.Other, (d[hostKey] as? String)?.takeIf { it.isNotEmpty() }, port)
    }
}

/** The CFNetwork key and type names, for tests that build an answer. */
internal object CfProxyKeys {
    val type: String get() = kCFProxyTypeKey.text()
    val host: String get() = kCFProxyHostNameKey.text()
    val port: String get() = kCFProxyPortNumberKey.text()
    val none: String get() = kCFProxyTypeNone.text()
    val https: String get() = kCFProxyTypeHTTPS.text()
    val socks: String get() = kCFProxyTypeSOCKS.text()
    val pac: String get() = kCFProxyTypeAutoConfigurationURL.text()
}
