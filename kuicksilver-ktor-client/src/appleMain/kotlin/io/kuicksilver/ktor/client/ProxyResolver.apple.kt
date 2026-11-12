// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import io.ktor.http.isSecure
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.StableRef
import kotlinx.cinterop.alloc
import kotlinx.cinterop.asStableRef
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.staticCFunction
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.CFNetwork.CFNetworkCopyProxiesForURL
import platform.CFNetwork.CFNetworkCopySystemProxySettings
import platform.CFNetwork.CFNetworkExecuteProxyAutoConfigurationScript
import platform.CFNetwork.CFNetworkExecuteProxyAutoConfigurationURL
import platform.CFNetwork.CFProxyAutoConfigurationResultCallback
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
import platform.CoreFoundation.CFArrayRef
import platform.CoreFoundation.CFErrorRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFRunLoopAddSource
import platform.CoreFoundation.CFRunLoopGetCurrent
import platform.CoreFoundation.CFRunLoopRemoveSource
import platform.CoreFoundation.CFRunLoopRunInMode
import platform.CoreFoundation.CFRunLoopSourceInvalidate
import platform.CoreFoundation.CFRunLoopStop
import platform.CoreFoundation.CFStreamClientContext
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFURLRef
import platform.CoreFoundation.kCFRunLoopDefaultMode
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSNumber
import platform.Foundation.NSURL
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.DurationUnit
import kotlin.time.TimeSource

internal actual val platformSystemProxyResolver: ProxyResolver = AppleSystemProxyResolver

/**
 * The system's proxy settings (`CFNetworkCopySystemProxySettings`) applied to the URL by `CFNetworkCopyProxiesForURL`,
 * which honours the exceptions list and "exclude simple host names". A PAC entry (a script's URL, which WPAD's discovery
 * gives too, or the script itself) is run by CFNetwork's PAC engine ([runPac]) with the URI of [pacTarget], within
 * [PAC_TIMEOUT_MILLIS]; a script that fails is skipped with a warning. The calls run on [Dispatchers.IO].
 */
internal object AppleSystemProxyResolver : WarningProxyResolver {
    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
    ): ResolvedProxy? {
        val host = socketHost(url.host)
        if (isLoopback(host)) return null
        val target = "${if (url.protocol.isSecure()) "https" else "http"}://${uriHost(host)}:${url.port}/"
        val pacTarget = pacTarget(url)
        return withContext(Dispatchers.IO) {
            pickCfProxy(systemProxies(target), { runPac(it.pacUrl, it.pacScript, pacTarget, PAC_TIMEOUT_MILLIS) }, warn)
        }
    }
}

/** What [runPac]'s callback found; written and read on the thread that runs the run loop. */
private class PacOutcome {
    var done: Boolean = false
    var proxies: List<CfProxy>? = null
}

/** CFNetwork's PAC callback: the answer (success) or nothing (an error); the list is read before the callback returns. */
private val pacCallback: CFProxyAutoConfigurationResultCallback =
    staticCFunction { client: COpaquePointer?, proxyList: CFArrayRef?, error: CFErrorRef? ->
        val outcome = client!!.asStableRef<PacOutcome>().get()
        outcome.done = true
        if (error == null && proxyList != null) {
            outcome.proxies = cfProxiesFrom(CFBridgingRelease(CFRetain(proxyList)) as? List<*> ?: emptyList<Any>())
        }
        CFRunLoopStop(CFRunLoopGetCurrent())
    }

/**
 * The run loop mode the PAC source runs in: the default one, as CFNetwork's download of a PAC URL runs there (with a mode
 * of its own the download never completed); the thread is one of `Dispatchers.IO`'s, which schedules nothing else on it.
 */
private val pacMode: CFStringRef get() = kCFRunLoopDefaultMode!!

/**
 * Runs the PAC script at [pacUrl] (downloaded by CFNetwork), or [pacScript], for [target] with
 * `CFNetworkExecuteProxyAutoConfigurationURL` / `…Script` on this thread's run loop, for at most [timeoutMillis]. The
 * script's answer as [CfProxy] entries, or null when it could not be fetched or run in time (the source is invalidated, so
 * nothing runs later).
 */
internal fun runPac(
    pacUrl: String?,
    pacScript: String?,
    target: String,
    timeoutMillis: Long,
): List<CfProxy>? {
    if (pacUrl == null && pacScript == null) return null
    val targetUrl = NSURL.URLWithString(target) ?: return null
    val outcome = PacOutcome()
    val ref = StableRef.create(outcome)
    try {
        memScoped {
            val context = alloc<CFStreamClientContext>()
            context.version = 0
            context.info = ref.asCPointer()
            context.retain = null
            context.release = null
            context.copyDescription = null

            @Suppress("UNCHECKED_CAST")
            val cfTarget = CFBridgingRetain(targetUrl) as CFURLRef
            try {
                val source =
                    if (pacScript != null) {
                        @Suppress("UNCHECKED_CAST")
                        val script = CFBridgingRetain(pacScript) as CFStringRef
                        try {
                            CFNetworkExecuteProxyAutoConfigurationScript(script, cfTarget, pacCallback, context.ptr)
                        } finally {
                            CFRelease(script)
                        }
                    } else {
                        val nsPac = NSURL.URLWithString(pacUrl!!) ?: return null

                        @Suppress("UNCHECKED_CAST")
                        val cfPac = CFBridgingRetain(nsPac) as CFURLRef
                        try {
                            CFNetworkExecuteProxyAutoConfigurationURL(cfPac, cfTarget, pacCallback, context.ptr)
                        } finally {
                            CFRelease(cfPac)
                        }
                    } ?: return null
                val loop = CFRunLoopGetCurrent()
                CFRunLoopAddSource(loop, source, pacMode)
                try {
                    val deadline = TimeSource.Monotonic.markNow() + timeoutMillis.milliseconds
                    while (!outcome.done) {
                        val left = -deadline.elapsedNow()
                        if (!left.isPositive()) break
                        CFRunLoopRunInMode(pacMode, left.toDouble(DurationUnit.SECONDS), false)
                    }
                } finally {
                    CFRunLoopRemoveSource(loop, source, pacMode)
                    CFRunLoopSourceInvalidate(source)
                    CFRelease(source)
                }
            } finally {
                CFRelease(cfTarget)
            }
        }
    } finally {
        ref.dispose()
    }
    return outcome.proxies
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
