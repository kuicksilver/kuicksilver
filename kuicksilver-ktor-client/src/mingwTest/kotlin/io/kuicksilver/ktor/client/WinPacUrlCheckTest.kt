// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlinx.cinterop.toKString
import platform.posix.getenv
import kotlin.test.Test

/**
 * Manual check (not part of the gate): what URL WinHTTP's PAC engine hands the script for a WebSocket (RFC 6455 section
 * 4.1) when the engine passes it whole (`pacFullWebSocketUrl`, the settings' PAC URL). Runs only with `KSL_WIN_PAC_URL`
 * set to the URL of the echo script `tools/check/win-pac-echo.pac`; prints what the script saw for each target. Steps:
 * tools/check/win-pac-check.md.
 */
class WinPacUrlCheckTest {
    @Test fun printWhatTheScriptSees() {
        val pacUrl = getenv("KSL_WIN_PAC_URL")?.toKString() ?: return
        val settings = IeProxySettings(autoDetect = false, autoConfigUrl = pacUrl, proxy = null, bypass = null)
        for (target in listOf("wss://h.test:8443/chat?room=1", "ws://h.test:8080/chat?room=1", "https://h.test/a/b?c=1")) {
            val answer = winHttpPac(settings, Url(target), WpadFailures(), fullWebSocketUrl = true)
            val seen = (answer as? WinPacAnswer.Proxies)?.proxy ?: answer.toString()
            println("WINPAC $target -> $seen")
        }
    }
}
