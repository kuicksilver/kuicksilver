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
 * (`Proxy-Authorization`, RFC 9110 section 11.7.2, RFC 7617). [toString] leaves the password out, and [hashCode]
 * depends on the user name only.
 */
@ExperimentalKuicksilverApi
public class ProxyCredentials(
    /** The user name. */
    public val user: String,
    /** The password. */
    public val password: String,
) {
    /** An opaque number of this instance, for the connection pool's key: nothing derived from the password goes there. */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    internal val id: Long = nextCredentialsId.addAndFetch(1L)

    override fun equals(other: Any?): Boolean = other is ProxyCredentials && other.user == user && other.password == password

    override fun hashCode(): Int = user.hashCode()

    override fun toString(): String = "ProxyCredentials(user=$user, password=***)"
}

@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
private val nextCredentialsId = kotlin.concurrent.atomics.AtomicLong(0)

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
 * A proxy as the engine uses it, what a [ProxyResolver] answers: HTTP ([http]: CONNECT tunnels for TLS and WebSockets,
 * the absolute form for plain http) or SOCKS5 ([socks5]: CONNECT only, RFC 1928), with the credentials to present and,
 * for SOCKS5, whether the proxy resolves the origin's name ([remoteDns], `socks5h`) or the engine sends it an address it
 * resolved itself (`socks5`). [toString] leaves the credentials out.
 */
@ExperimentalKuicksilverApi
public class ResolvedProxy private constructor(
    internal val kind: Kind,
    /** The proxy's host: a name or an IP literal (without brackets). */
    public val host: String,
    /** The proxy's port, 1..65535. */
    public val port: Int,
    /** What to authenticate with, or null. */
    public val credentials: ProxyCredentials?,
    /** SOCKS5 only: true sends the origin's name for the proxy to resolve, false an address the engine resolved. */
    public val remoteDns: Boolean,
) {
    internal enum class Kind { Http, Socks5 }

    init {
        require(host.isNotEmpty()) { "a proxy needs a host" }
        require(port in 1..0xffff) { "proxy port out of range: $port" }
    }

    /** [ProxyType.HTTP] or [ProxyType.SOCKS] (SOCKS5). */
    public val type: ProxyType get() = if (kind == Kind.Http) ProxyType.HTTP else ProxyType.SOCKS

    /**
     * Part of the connection pool's key: another proxy, or another [ProxyCredentials] instance, is another route. The
     * instance's opaque id stands for the credentials, so nothing derived from the password is kept or compared there.
     */
    internal val routeKey: String get() = "$kind://${uriHost(host)}:$port#${credentials?.id ?: 0}/$remoteDns"

    /** `Basic` credentials for `Proxy-Authorization`, when there are credentials. */
    internal val basicAuthorization: String?
        get() = credentials?.let { "Basic " + Base64.encode("${it.user}:${it.password}".encodeToByteArray()) }

    override fun equals(other: Any?): Boolean =
        other is ResolvedProxy && other.kind == kind && other.host == host && other.port == port &&
            other.credentials == credentials && other.remoteDns == remoteDns

    override fun hashCode(): Int = ((kind.hashCode() * 31 + host.hashCode()) * 31 + port) * 31 + (credentials?.hashCode() ?: 0)

    override fun toString(): String =
        "${if (kind == Kind.Http) {
            "http"
        } else if (remoteDns) {
            "socks5h"
        } else {
            "socks5"
        }}://${uriHost(host)}:$port"

    /** Builds them. */
    public companion object {
        /** An HTTP proxy at [host]:[port] (spoken to in plain TCP; TLS to the proxy itself is not supported). */
        public fun http(
            host: String,
            port: Int,
            credentials: ProxyCredentials? = null,
        ): ResolvedProxy = ResolvedProxy(Kind.Http, socketHost(host), port, credentials, remoteDns = true)

        /** A SOCKS5 proxy at [host]:[port]; [remoteDns] true (`socks5h`) lets it resolve the origin's name. */
        public fun socks5(
            host: String,
            port: Int,
            credentials: ProxyCredentials? = null,
            remoteDns: Boolean = true,
        ): ResolvedProxy = ResolvedProxy(Kind.Socks5, socketHost(host), port, credentials, remoteDns)
    }
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
        throw UnsupportedOperationException(TLS_PROXY_UNSUPPORTED)
    }
    // a NetworkAddress (java.net's on the JVM, ktor-utils' on Native): its address, not a reverse lookup of it
    val address = resolveAddress()
    val credentials = platformProxyCredentials() ?: fallback
    return if (kind == ResolvedProxy.Kind.Http) {
        ResolvedProxy.http(address.address, address.port, credentials)
    } else {
        ResolvedProxy.socks5(address.address, address.port, credentials)
    }
}

/** The credentials in the proxy URL's user info, percent-decoded; null on the JVM and without user info. */
@OptIn(ExperimentalKuicksilverApi::class)
internal expect fun ProxyConfig.platformProxyCredentials(): ProxyCredentials?

/** Whether this is `java.net.Proxy.NO_PROXY` (only on the JVM). */
internal expect fun ProxyConfig.platformProxyIsDirect(): Boolean

/** Whether the proxy URL is `https://` (only expressible off the JVM). */
internal expect fun ProxyConfig.platformProxyUsesTls(): Boolean

/**
 * The proxy for a request to [url]: the engine's explicit `proxy` (with `proxyCredentials`), else what its
 * `proxyResolver` says (cached per route), null for a direct connection. Fails with UnsupportedOperationException for a
 * proxy the engine cannot use, so a request never bypasses it.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun KuicksilverEngine.proxyFor(url: io.ktor.http.Url): ResolvedProxy? =
    if (config.proxy == null) proxies.lookup(url) else proxies.explicit()
