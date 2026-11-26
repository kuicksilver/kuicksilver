// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.http.Url
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.UdpProxyTemplate
import kotlin.io.encoding.Base64

/**
 * A CONNECT-UDP proxy (RFC 9298, MASQUE) for the engine's HTTP/3: `engine { connectUdpProxy = ConnectUdpProxy(template) }`.
 * Each HTTP/3 connection to an origin it [applies][ConnectUdpProxy.applies] to runs inside a UDP tunnel through the proxy
 * (`Http3Connection.connectUdp` on a connection to the proxy, the tunnel as the inner connection's socket), with TLS end to
 * end to the origin: the proxy sees the origin's name and port and UDP, never the requests.
 *
 * @property template the proxy's URI Template (RFC 9298 section 2), checked when it was parsed; its authority is the proxy's
 *   host and port (443 when it has none), reached over HTTP/3 directly with the proxy's TLS settings
 *   (`proxies { tls { } }`, by default the engine's trust without what names the origin and without the client
 *   certificate, as an `https://` proxy over TCP; ADR-0023); a failed handshake with it is a [ProxyTlsException].
 * @property credentials sent to the proxy as `proxy-authorization: Basic ...` on each tunnel's CONNECT, never to the origin;
 *   null for none. A user name with a colon, or control characters in either part, fail here with IllegalArgumentException
 *   (RFC 7617 section 2).
 * @property applies whether a request's URL goes through the proxy; every `https` URL by default. A URL it does not apply to
 *   takes the engine's usual path (its HTTP/SOCKS proxy settings, Alt-Svc, the race).
 */
@ExperimentalKuicksilverApi
public class ConnectUdpProxy(
    public val template: UdpProxyTemplate,
    public val credentials: ProxyCredentials? = null,
    public val applies: (Url) -> Boolean = { true },
) {
    /** The proxy's host (no brackets) and port, from the template's authority. */
    internal val host: String
    internal val port: Int

    init {
        val a = template.authority
        val (h, p) =
            if (a.startsWith('[')) {
                val end = a.indexOf(']')
                require(end > 0) { "the proxy template's authority is not a host: $a" }
                a.substring(1, end) to a.substring(end + 1).removePrefix(":")
            } else {
                a.substringBefore(':') to (if (':' in a) a.substringAfter(':') else "")
            }
        host = h
        port =
            if (p.isEmpty()) 443 else p.toIntOrNull()?.takeIf { it in 1..65535 } ?: throw IllegalArgumentException("bad proxy port in $a")
        require(host.isNotEmpty()) { "the proxy template's authority has no host: $a" }
        credentials?.let { requireBasicCredentials(it) }
    }

    /** `Proxy-Authorization` for the tunnels' CONNECT, or null. */
    internal val authorization: String?
        get() = credentials?.let { "Basic " + Base64.encode("${it.user}:${it.password}".encodeToByteArray()) }

    /** Part of a pooled connection's key: another proxy or another credentials instance is another route. */
    internal val routeKey: String get() = "udp:${template.template}#${credentials?.id ?: 0}"

    /** For logs: the template, never the credentials. */
    override fun toString(): String = "ConnectUdpProxy(${template.template})"
}
