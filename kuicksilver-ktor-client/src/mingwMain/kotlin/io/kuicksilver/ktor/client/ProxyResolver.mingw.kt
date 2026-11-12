// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.toKString
import kotlinx.cinterop.wcstr
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.windows.GetLastError
import platform.windows.GlobalFree
import platform.winhttp.ERROR_WINHTTP_UNRECOGNIZED_SCHEME
import platform.winhttp.WINHTTP_ACCESS_TYPE_NAMED_PROXY
import platform.winhttp.WINHTTP_ACCESS_TYPE_NO_PROXY
import platform.winhttp.WINHTTP_AUTOPROXY_AUTO_DETECT
import platform.winhttp.WINHTTP_AUTOPROXY_CONFIG_URL
import platform.winhttp.WINHTTP_AUTOPROXY_OPTIONS
import platform.winhttp.WINHTTP_AUTO_DETECT_TYPE_DHCP
import platform.winhttp.WINHTTP_AUTO_DETECT_TYPE_DNS_A
import platform.winhttp.WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
import platform.winhttp.WINHTTP_PROXY_INFO
import platform.winhttp.WinHttpCloseHandle
import platform.winhttp.WinHttpGetIEProxyConfigForCurrentUser
import platform.winhttp.WinHttpGetProxyForUrl
import platform.winhttp.WinHttpOpen
import platform.winhttp.WinHttpSetTimeouts

internal actual val platformSystemProxyResolver: ProxyResolver = WindowsSystemProxyResolver

/**
 * `WinHttpGetIEProxyConfigForCurrentUser`, applied as WinHTTP and Internet Explorer apply it ([windowsProxyFor]):
 * automatic detection (WPAD) and a configuration script (PAC) are run by `WinHttpGetProxyForUrl` ([winHttpPac]); when
 * neither is set, or the script fails (a warning), the fixed proxy list and its bypass list. The calls run on
 * [Dispatchers.IO].
 */
internal object WindowsSystemProxyResolver : WarningProxyResolver {
    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
    ): ResolvedProxy? {
        if (isLoopback(socketHost(url.host))) return null
        return withContext(Dispatchers.IO) {
            val s = ieProxySettings() ?: return@withContext null
            windowsProxyFor(s, url, { winHttpPac(s, url) }, warn)
        }
    }
}

/**
 * Runs the automatic detection (DHCP, then DNS) and the PAC URL of [s] for [url] with `WinHttpGetProxyForUrl`, WinHTTP's
 * own PAC engine, on a session of its own whose timeouts are [PAC_TIMEOUT_MILLIS] (the script's download). The URI given
 * to the script is [pacTarget]'s; WinHTTP knows only `http` and `https`, so a WebSocket's `ws://`/`wss://` URI it refuses
 * as an unknown scheme goes again as `http://`/`https://` with the same host, port and resource name.
 */
internal fun winHttpPac(
    s: IeProxySettings,
    url: Url,
): WinPacAnswer {
    val session =
        WinHttpOpen("Kuicksilver", WINHTTP_ACCESS_TYPE_NO_PROXY.toUInt(), null, null, 0u) ?: return WinPacAnswer.Failed
    try {
        val t = PAC_TIMEOUT_MILLIS.toInt()
        WinHttpSetTimeouts(session, t, t, t, t)
        val target = pacTarget(url)
        val (answer, error) = winHttpProxyForUrl(session, s, target)
        if (error == ERROR_WINHTTP_UNRECOGNIZED_SCHEME.toUInt() && (target.startsWith("ws://") || target.startsWith("wss://"))) {
            return winHttpProxyForUrl(session, s, "http" + target.removePrefix("ws")).first
        }
        return answer
    } finally {
        WinHttpCloseHandle(session)
    }
}

/** One `WinHttpGetProxyForUrl` call for [target]: the answer, and the error code when it failed (0 otherwise). */
private fun winHttpProxyForUrl(
    session: COpaquePointer,
    s: IeProxySettings,
    target: String,
): Pair<WinPacAnswer, UInt> =
    memScoped {
        val options = alloc<WINHTTP_AUTOPROXY_OPTIONS>()
        var flags = 0
        if (s.autoDetect) flags = flags or WINHTTP_AUTOPROXY_AUTO_DETECT
        if (s.autoConfigUrl != null) flags = flags or WINHTTP_AUTOPROXY_CONFIG_URL
        options.dwFlags = flags.toUInt()
        options.dwAutoDetectFlags = if (s.autoDetect) (WINHTTP_AUTO_DETECT_TYPE_DHCP or WINHTTP_AUTO_DETECT_TYPE_DNS_A).toUInt() else 0u
        options.lpszAutoConfigUrl = s.autoConfigUrl?.wcstr?.ptr
        options.fAutoLogonIfChallenged = 1
        val info = alloc<WINHTTP_PROXY_INFO>()
        if (WinHttpGetProxyForUrl(session, target, options.ptr, info.ptr) == 0) {
            return@memScoped WinPacAnswer.Failed to GetLastError()
        }
        try {
            val answer =
                if (info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY.toUInt()) {
                    WinPacAnswer.Proxies(
                        info.lpszProxy?.toKString()?.takeIf { it.isNotEmpty() },
                        info.lpszProxyBypass?.toKString()?.takeIf { it.isNotEmpty() },
                    )
                } else {
                    WinPacAnswer.Direct
                }
            answer to 0u
        } finally {
            info.lpszProxy?.let { GlobalFree(it) }
            info.lpszProxyBypass?.let { GlobalFree(it) }
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
