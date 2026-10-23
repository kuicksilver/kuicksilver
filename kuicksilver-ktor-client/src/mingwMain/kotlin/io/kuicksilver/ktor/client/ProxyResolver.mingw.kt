// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.toKString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.windows.GlobalFree
import platform.winhttp.WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
import platform.winhttp.WinHttpGetIEProxyConfigForCurrentUser

internal actual val platformSystemProxyResolver: ProxyResolver = WindowsSystemProxyResolver

/** The user's Internet settings, as WinHTTP reads them. */
internal class IeProxySettings(
    val autoDetect: Boolean,
    val autoConfigUrl: String?,
    val proxy: String?,
    val bypass: String?,
)

/**
 * `WinHttpGetIEProxyConfigForCurrentUser`: the fixed proxy list and its bypass list; automatic detection (WPAD) or a
 * configuration script (PAC) is not run, which logs a warning, while a fixed proxy configured next to it is still used.
 */
internal object WindowsSystemProxyResolver : WarningProxyResolver {
    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
    ): ResolvedProxy? {
        if (isLoopback(socketHost(url.host))) return null
        val s = withContext(Dispatchers.IO) { ieProxySettings() } ?: return null
        if (s.autoDetect || s.autoConfigUrl != null) warn(PAC_WARNING)
        return parseWinInetProxy(s.proxy, s.bypass, url)
    }
}

/** The current user's settings, or null when WinHTTP cannot read them; the strings it allocated are freed. */
internal fun ieProxySettings(): IeProxySettings? =
    memScoped {
        val config = alloc<WINHTTP_CURRENT_USER_IE_PROXY_CONFIG>()
        if (WinHttpGetIEProxyConfigForCurrentUser(config.ptr) == 0) return null
        ieProxySettingsFrom(config)
    }

/** Reads [config] and frees its strings (the caller owns them, as after `WinHttpGetIEProxyConfigForCurrentUser`). */
internal fun ieProxySettingsFrom(config: WINHTTP_CURRENT_USER_IE_PROXY_CONFIG): IeProxySettings {
    try {
        return IeProxySettings(
            autoDetect = config.fAutoDetect != 0,
            autoConfigUrl = config.lpszAutoConfigUrl?.toKString()?.takeIf { it.isNotEmpty() },
            proxy = config.lpszProxy?.toKString()?.takeIf { it.isNotEmpty() },
            bypass = config.lpszProxyBypass?.toKString()?.takeIf { it.isNotEmpty() },
        )
    } finally {
        config.lpszAutoConfigUrl?.let { GlobalFree(it) }
        config.lpszProxy?.let { GlobalFree(it) }
        config.lpszProxyBypass?.let { GlobalFree(it) }
    }
}
