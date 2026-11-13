// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import io.ktor.http.isSecure
import io.kuicksilver.ktor.client.pac.evaluatePac
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.CFNetwork.CFNetworkCopyProxiesForURL
import platform.CFNetwork.CFNetworkCopySystemProxySettings
import platform.CFNetwork.kCFProxyAutoConfigurationJavaScriptKey
import platform.CFNetwork.kCFProxyAutoConfigurationURLKey
import platform.CFNetwork.kCFProxyHostNameKey
import platform.CFNetwork.kCFProxyPortNumberKey
import platform.CFNetwork.kCFProxyTypeAutoConfigurationJavaScript
import platform.CFNetwork.kCFProxyTypeAutoConfigurationURL
import platform.CFNetwork.kCFProxyTypeHTTP
import platform.CFNetwork.kCFProxyTypeHTTPS
import platform.CFNetwork.kCFProxyTypeKey
import platform.CFNetwork.kCFProxyTypeNone
import platform.CFNetwork.kCFProxyTypeSOCKS
import platform.CoreFoundation.CFDictionaryRef
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
 * which honours the exceptions list and "exclude simple host names". A PAC entry (a script's URL or the script itself),
 * and WPAD's discovery when the settings say "auto discover" and CFNetwork gives no PAC entry, is run by the engine's
 * own PAC engine ([evaluatePac]: the script downloaded by the engine, run on JavaScriptCore) with the URI of
 * [applePacTarget] (for `https` and `wss` the origin only, unless the opt-in and the entry allow more), within
 * [PAC_TIMEOUT_MILLIS]; a script that fails is skipped with a warning. The system calls run on [Dispatchers.IO].
 */
internal object AppleSystemProxyResolver : WarningProxyResolver {
    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
    ): ResolvedProxy? = proxyFor(url, warn, pacFullWebSocketUrl = false)

    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
        pacFullWebSocketUrl: Boolean,
    ): ResolvedProxy? {
        val host = socketHost(url.host)
        if (isLoopback(host)) return null
        val target = "${if (url.protocol.isSecure()) "https" else "http"}://${uriHost(host)}:${url.port}/"
        val scriptHost = pacHost(url)
        val settings = withContext(Dispatchers.IO) { systemProxySettings(target) }
        val entries = settings.entries
        val all =
            if (settings.autoDiscover && entries.none { it.type == CfProxy.Type.AutoConfiguration }) {
                listOf(CfProxy(CfProxy.Type.AutoConfiguration, null, null, wpad = true)) + entries
            } else {
                entries
            }
        return pickCfProxyWithPac(all, { evaluatePac(it, applePacTarget(url, it, settings, pacFullWebSocketUrl), scriptHost) }, warn)
    }
}

/**
 * The URI [entry]'s script gets for [url] ([pacTarget]): a `wss` URI whole only with [fullWebSocketUrl] and only when the
 * entry is the PAC the settings name (`ProxyAutoConfigEnable` on) and out of the local network's reach: the settings'
 * own script (`ProxyAutoConfigJavaScript`), or their PAC URL (`ProxyAutoConfigURLString`) when it is `https` or `file`
 * ([pacUrlIsPrivate]). The entry's URL (CFNetwork's `absoluteString`) must equal the settings' string exactly; one
 * written otherwise gets the origin, as do a script WPAD found, one over plain `http`, and an entry the settings do not
 * name.
 */
internal fun applePacTarget(
    url: Url,
    entry: CfProxy,
    settings: SystemProxySettings,
    fullWebSocketUrl: Boolean,
): String {
    val named =
        !entry.wpad &&
            settings.pacEnabled &&
            (
                (entry.pacUrl != null && entry.pacUrl == settings.pacUrl && pacUrlIsPrivate(entry.pacUrl)) ||
                    (entry.pacScript != null && entry.pacScript == settings.pacScript)
            )
    return pacTarget(url, fullWebSocketUrl && named)
}

/**
 * What [systemProxySettings] read: whether they say "auto discover" (WPAD), the PAC they name ([pacEnabled]: a script's
 * URL or the script), and what CFNetwork says for the URL, in its order.
 */
internal class SystemProxySettings(
    val autoDiscover: Boolean,
    val entries: List<CfProxy>,
    val pacEnabled: Boolean = false,
    val pacUrl: String? = null,
    val pacScript: String? = null,
)

/** The system's proxy settings and what CFNetwork says for [urlString] under them. */
internal fun systemProxySettings(urlString: String): SystemProxySettings {
    val settings = CFNetworkCopySystemProxySettings() ?: return SystemProxySettings(false, emptyList())
    try {
        val dict = CFBridgingRelease(CFRetain(settings)) as? Map<*, *>
        return SystemProxySettings(
            autoDiscover = (dict?.get("ProxyAutoDiscoveryEnable") as? Number)?.toInt() == 1,
            entries = proxiesFor(urlString, settings),
            pacEnabled = (dict?.get("ProxyAutoConfigEnable") as? Number)?.toInt() == 1,
            pacUrl = dict?.get("ProxyAutoConfigURLString") as? String,
            pacScript = dict?.get("ProxyAutoConfigJavaScript") as? String,
        )
    } finally {
        CFRelease(settings)
    }
}

/** What CFNetwork says for [urlString], in its order. */
internal fun systemProxies(urlString: String): List<CfProxy> = systemProxySettings(urlString).entries

/** `CFNetworkCopyProxiesForURL` of [urlString] under [settings] (read once per lookup). */
private fun proxiesFor(
    urlString: String,
    settings: CFDictionaryRef,
): List<CfProxy> {
    val nsUrl = NSURL.URLWithString(urlString) ?: return emptyList()

    @Suppress("UNCHECKED_CAST")
    val cfUrl = CFBridgingRetain(nsUrl) as CFURLRef
    try {
        val proxies = CFNetworkCopyProxiesForURL(cfUrl, settings) ?: return emptyList()
        return cfProxiesFrom(CFBridgingRelease(proxies) as? List<*> ?: return emptyList())
    } finally {
        CFRelease(cfUrl)
    }
}

private fun CFStringRef?.text(): String = CFBridgingRelease(CFRetain(this)) as String

/** The proxy dictionaries of a `CFNetworkCopyProxiesForURL` answer as [CfProxy] entries. */
internal fun cfProxiesFrom(list: List<*>): List<CfProxy> {
    val typeKey = kCFProxyTypeKey.text()
    val hostKey = kCFProxyHostNameKey.text()
    val portKey = kCFProxyPortNumberKey.text()
    val pacUrlKey = kCFProxyAutoConfigurationURLKey.text()
    val pacScriptKey = kCFProxyAutoConfigurationJavaScriptKey.text()
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
        // the PAC URL is a CFURL in CFNetwork's answer (a string when a test builds one)
        val pacUrl = (d[pacUrlKey] as? NSURL)?.absoluteString ?: d[pacUrlKey] as? String
        CfProxy(
            types[d[typeKey] as? String] ?: CfProxy.Type.Other,
            (d[hostKey] as? String)?.takeIf { it.isNotEmpty() },
            port,
            pacUrl = pacUrl,
            pacScript = d[pacScriptKey] as? String,
        )
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
    val pacScriptType: String get() = kCFProxyTypeAutoConfigurationJavaScript.text()
    val pacUrl: String get() = kCFProxyAutoConfigurationURLKey.text()
    val pacScript: String get() = kCFProxyAutoConfigurationJavaScriptKey.text()
}
