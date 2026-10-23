// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.http.Url
import io.ktor.http.isSecure
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.URI

internal actual fun platformGetenv(name: String): String? = System.getenv(name)

internal actual val platformSystemProxyResolver: ProxyResolver = JvmSystemProxyResolver

/**
 * `ProxySelector.getDefault()`: the JDK's selector reads `https.proxyHost`, `http.proxyHost`, `socksProxyHost`,
 * `http.nonProxyHosts` and, with `java.net.useSystemProxies`, the OS settings; on Android it is the active network's
 * proxy, PAC included. Its first answer is used; SOCKS means SOCKS5 with the proxy resolving names. It runs on
 * [Dispatchers.IO]: a selector may look things up.
 */
internal object JvmSystemProxyResolver : ProxyResolver {
    override suspend fun proxyFor(url: Url): ResolvedProxy? {
        val host = socketHost(url.host)
        if (isLoopback(host)) return null
        val uri = URI(if (url.protocol.isSecure()) "https" else "http", null, host, url.port, "/", null, null)
        val proxy = withContext(Dispatchers.IO) { ProxySelector.getDefault()?.select(uri)?.firstOrNull() } ?: return null
        if (proxy.type() == Proxy.Type.DIRECT) return null
        val address =
            proxy.address() as? InetSocketAddress
                ?: throw UnsupportedOperationException("the default ProxySelector gave a proxy without a socket address")
        return if (proxy.type() == Proxy.Type.HTTP) {
            ResolvedProxy.http(address.hostString, address.port)
        } else {
            ResolvedProxy.socks5(address.hostString, address.port)
        }
    }
}
