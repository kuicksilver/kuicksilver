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
import platform.winhttp.ERROR_WINHTTP_AUTODETECTION_FAILED
import platform.winhttp.ERROR_WINHTTP_LOGIN_FAILURE
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
 * automatic detection (WPAD) and a configuration script (PAC) are run by `WinHttpGetProxyForUrl` ([winHttpPac]), and a
 * lookup waits for them at most [PAC_TIMEOUT_MILLIS] ([BoundedPac]); when neither is set, detection found no script, or
 * the script failed (a warning), the fixed proxy list and its bypass list. The calls run on [Dispatchers.IO].
 */
internal object WindowsSystemProxyResolver : WarningProxyResolver {
    private val wpad = WpadFailures()
    private val bounded = BoundedPac(PAC_TIMEOUT_MILLIS)

    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
    ): ResolvedProxy? = proxyFor(url, warn, pacFullWebSocketUrl = false)

    override suspend fun proxyFor(
        url: Url,
        warn: (String) -> Unit,
        pacFullWebSocketUrl: Boolean,
    ): ResolvedProxy? {
        if (isLoopback(socketHost(url.host))) return null
        val s = withContext(Dispatchers.IO) { ieProxySettings() } ?: return null
        // windowsProxyFor asks for the answer only when detection or a script URL is set
        val answer =
            if (s.autoDetect || s.autoConfigUrl != null) bounded.run { winHttpPac(s, url, wpad, pacFullWebSocketUrl) } else null
        return windowsProxyFor(s, url, { answer ?: WinPacAnswer.Failed }, warn)
    }
}

/**
 * Runs the automatic detection (DHCP, then DNS) and the PAC URL of [s] for [url] with `WinHttpGetProxyForUrl`, WinHTTP's
 * own PAC engine, in [runWinPac]'s order, on a session of its own whose timeouts are [PAC_TIMEOUT_MILLIS] (they bound
 * each step of the script's download; detection and the script's run have none of WinHTTP's, the caller's [BoundedPac]
 * bounds the wait). The URI given to the script is [winPacTarget]'s: for `https` and `wss` the origin only, a `wss`
 * URI whole only for the settings' PAC URL when `https` or local `file` with [fullWebSocketUrl], never for a script automatic
 * detection found.
 * WinHTTP knows only `http` and `https`, so a WebSocket's `ws://`/`wss://` URI it refuses as an unknown scheme goes
 * again as `http://`/`https://` with the same host, port and resource name.
 */
internal fun winHttpPac(
    s: IeProxySettings,
    url: Url,
    wpad: WpadFailures,
    fullWebSocketUrl: Boolean = false,
): WinPacAnswer {
    val session =
        WinHttpOpen("Kuicksilver", WINHTTP_ACCESS_TYPE_NO_PROXY.toUInt(), null, null, 0u) ?: return WinPacAnswer.Failed
    try {
        val t = PAC_TIMEOUT_MILLIS.toInt()
        WinHttpSetTimeouts(session, t, t, t, t)
        return runWinPac(s, wpad) { detect, configUrl, autoLogon ->
            val target = winPacTarget(url, detect, configUrl, fullWebSocketUrl)
            val (answer, error) = winHttpProxyForUrl(session, detect, configUrl, autoLogon, target)
            if (error == ERROR_WINHTTP_UNRECOGNIZED_SCHEME.toUInt() && (target.startsWith("ws://") || target.startsWith("wss://"))) {
                val (again, againError) = winHttpProxyForUrl(session, detect, configUrl, autoLogon, "http" + target.removePrefix("ws"))
                winPacCall(again, againError)
            } else {
                winPacCall(answer, error)
            }
        }
    } finally {
        WinHttpCloseHandle(session)
    }
}

/** One call's [answer] and [error] code as [runWinPac] tells them apart. */
private fun winPacCall(
    answer: WinPacAnswer,
    error: UInt,
): WinPacCall =
    when (error) {
        0u -> WinPacCall.Answer(answer)
        ERROR_WINHTTP_AUTODETECTION_FAILED.toUInt() -> WinPacCall.NoWpad
        ERROR_WINHTTP_LOGIN_FAILURE.toUInt() -> WinPacCall.LoginFailure
        else -> WinPacCall.Failed
    }

/**
 * One `WinHttpGetProxyForUrl` call for [target]: with automatic detection when [detect], else with the script at
 * [configUrl]; [autoLogon] is `fAutoLogonIfChallenged`. The answer, and the error code when it failed (0 otherwise).
 */
private fun winHttpProxyForUrl(
    session: COpaquePointer,
    detect: Boolean,
    configUrl: String?,
    autoLogon: Boolean,
    target: String,
): Pair<WinPacAnswer, UInt> =
    memScoped {
        val options = alloc<WINHTTP_AUTOPROXY_OPTIONS>()
        options.dwFlags = (if (detect) WINHTTP_AUTOPROXY_AUTO_DETECT else WINHTTP_AUTOPROXY_CONFIG_URL).toUInt()
        options.dwAutoDetectFlags = if (detect) (WINHTTP_AUTO_DETECT_TYPE_DHCP or WINHTTP_AUTO_DETECT_TYPE_DNS_A).toUInt() else 0u
        options.lpszAutoConfigUrl = if (detect) null else configUrl?.wcstr?.ptr
        options.fAutoLogonIfChallenged = if (autoLogon) 1 else 0
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
