// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import kotlinx.cinterop.UShortVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import platform.windows.GMEM_FIXED
import platform.windows.GlobalAlloc
import platform.winhttp.WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The WinHTTP structure as the Windows `System` resolver reads it, built here (the host's settings are not read). */
class SystemProxyWindowsTest {
    /** A wide string in GlobalAlloc memory, as WinHTTP hands them out. */
    private fun global(s: String) =
        GlobalAlloc(GMEM_FIXED.toUInt(), ((s.length + 1) * 2).toULong())!!.reinterpret<UShortVar>().also { p ->
            s.forEachIndexed { i, c -> p[i] = c.code.toUShort() }
            p[s.length] = 0u
        }

    @Test fun readsIeProxyConfig() =
        memScoped {
            val config = alloc<WINHTTP_CURRENT_USER_IE_PROXY_CONFIG>()
            config.fAutoDetect = 1
            config.lpszProxy = global("http=a:1;https=b:2")
            config.lpszProxyBypass = global("<local>")
            val s = ieProxySettingsFrom(config)
            assertTrue(s.autoDetect)
            assertNull(s.autoConfigUrl)
            assertEquals(ResolvedProxy.http("b", 2), parseWinInetProxy(s.proxy, s.bypass, Url("https://x.test/")))
            assertNull(parseWinInetProxy(s.proxy, s.bypass, Url("https://intranet/")))
        }

    @Test fun currentUserSettingsRead() {
        ieProxySettings() // whatever this host has; it must not fail
    }
}
