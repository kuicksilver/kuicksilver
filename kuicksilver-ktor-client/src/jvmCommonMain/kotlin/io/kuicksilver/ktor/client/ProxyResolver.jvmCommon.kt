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

/**
 * The URI `ProxySelector.select` gets for [url]: `http` or `https`, the host and port, and for a WebSocket its resource
 * name (path and query). RFC 6455 section 4.1: "the URI to pass the function MUST be constructed from /host/, /port/,
 * /resource name/, and the /secure/ flag"; the selectors know only `http` and `https` (the JDK's gives `ws` and `wss` no
 * proxy at all), so `ws` maps to `http` and `wss` to `https`, the secure flag kept. Other requests give the
 * path `/` (the answers are kept per scheme, host and port).
 */
internal fun selectorUri(url: Url): URI {
    val host = socketHost(url.host)
    val scheme = if (url.protocol.isSecure()) "https" else "http"
    if (url.protocol.name == "ws" || url.protocol.name == "wss") {
        runCatching { URI("$scheme://${uriHost(host)}:${url.port}${url.encodedPathAndQuery.ifEmpty { "/" }}") }
            .getOrNull()
            ?.let { return it }
    }
    return URI(scheme, null, host, url.port, "/", null, null)
}

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
        val uri = selectorUri(url)
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
