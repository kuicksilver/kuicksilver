// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyConfig
import io.ktor.client.engine.ProxyType
import io.ktor.client.engine.resolveAddress
import io.ktor.client.engine.type
import io.ktor.util.network.address
import io.ktor.util.network.port
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import kotlinx.io.IOException
import kotlin.io.encoding.Base64

/**
 * A user name and password for a proxy: SOCKS5 username/password authentication (RFC 1929) or HTTP `Basic`
 * (`Proxy-Authorization`, RFC 9110 section 11.7.2, RFC 7617). [toString] leaves the password out.
 */
@ExperimentalKuicksilverApi
public class ProxyCredentials(
    /** The user name. */
    public val user: String,
    /** The password. */
    public val password: String,
) {
    override fun equals(other: Any?): Boolean = other is ProxyCredentials && other.user == user && other.password == password

    override fun hashCode(): Int = user.hashCode() * 31 + password.hashCode()

    override fun toString(): String = "ProxyCredentials(user=$user, password=***)"
}

/**
 * A proxy refused or failed the request's connection: a SOCKS5 reply other than "succeeded" ([replyCode] is its REP
 * field, RFC 1928 section 6), a SOCKS5 authentication the proxy rejected ([replyCode] null), or a status other than 2xx in
 * answer to an HTTP CONNECT ([replyCode] is the status, 407 when the proxy wants credentials). The message names the
 * proxy, never the credentials.
 */
@ExperimentalKuicksilverApi
public class ProxyException(
    message: String,
    /** The SOCKS5 reply code or the HTTP status of the CONNECT response; null when the proxy gave none. */
    public val replyCode: Int?,
) : IOException(message)

/**
 * A proxy as the engine uses it: HTTP (CONNECT tunnels for TLS and WebSockets, the absolute form for plain http) or
 * SOCKS5 (CONNECT only, RFC 1928), with the credentials to present and, for SOCKS5, whether the proxy resolves the
 * origin's name ([remoteDns], `socks5h`) or the engine sends it an address it resolved itself (`socks5`).
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal class ResolvedProxy(
    val kind: Kind,
    val host: String,
    val port: Int,
    val credentials: ProxyCredentials?,
    val remoteDns: Boolean = true,
) {
    enum class Kind { Http, Socks5 }

    /** Part of the connection pool's key: another proxy, or other credentials, is another route. */
    val routeKey: String get() = "$kind://${uriHost(host)}:$port#${credentials?.hashCode() ?: 0}/$remoteDns"

    /** `Basic` credentials for `Proxy-Authorization`, when there are credentials. */
    val basicAuthorization: String?
        get() = credentials?.let { "Basic " + Base64.encode("${it.user}:${it.password}".encodeToByteArray()) }

    override fun toString(): String = "${if (kind == Kind.Http) "http" else "socks5"}://${uriHost(host)}:$port"
}

/**
 * The engine's `proxy` as a [ResolvedProxy], null for `java.net.Proxy.NO_PROXY` (a direct connection). Credentials come from the proxy URL's user info (not on the JVM, whose
 * `ProxyConfig` is a `java.net.Proxy` without them), else [fallback]. A proxy the engine cannot use fails with
 * UnsupportedOperationException rather than being bypassed: an `https://` proxy URL (TLS to the proxy itself is not
 * supported) or a type other than HTTP and SOCKS.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun ProxyConfig.toResolvedProxy(fallback: ProxyCredentials?): ResolvedProxy? {
    if (platformProxyIsDirect()) return null
    val kind =
        when (type) {
            ProxyType.HTTP -> ResolvedProxy.Kind.Http
            ProxyType.SOCKS -> ResolvedProxy.Kind.Socks5
            ProxyType.UNKNOWN -> throw UnsupportedOperationException("the Kuicksilver engine supports HTTP and SOCKS5 proxies only")
        }
    if (kind == ResolvedProxy.Kind.Http && platformProxyUsesTls()) {
        throw UnsupportedOperationException(
            "an https:// proxy (TLS to the proxy) is not supported; use an http:// proxy, whose CONNECT tunnels still carry TLS",
        )
    }
    // a NetworkAddress (java.net's on the JVM, ktor-utils' on Native): its address, not a reverse lookup of it
    val address = resolveAddress()
    return ResolvedProxy(kind, socketHost(address.address), address.port, platformProxyCredentials() ?: fallback)
}

/** The credentials in the proxy URL's user info, percent-decoded; null on the JVM and without user info. */
@OptIn(ExperimentalKuicksilverApi::class)
internal expect fun ProxyConfig.platformProxyCredentials(): ProxyCredentials?

/** Whether this is `java.net.Proxy.NO_PROXY` (only on the JVM). */
internal expect fun ProxyConfig.platformProxyIsDirect(): Boolean

/** Whether the proxy URL is `https://` (only expressible off the JVM). */
internal expect fun ProxyConfig.platformProxyUsesTls(): Boolean

/**
 * The proxy for a request to [url]: the engine's explicit `proxy` (with `proxyCredentials`), null for a direct
 * connection. Fails with UnsupportedOperationException for a proxy the engine cannot use, so a request never bypasses it.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun KuicksilverEngine.proxyFor(
    @Suppress("UNUSED_PARAMETER") url: io.ktor.http.Url,
): ResolvedProxy? = config.proxy?.toResolvedProxy(config.proxyCredentials)
