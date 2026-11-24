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
 * (`Proxy-Authorization`, RFC 9110 section 11.7.2, RFC 7617). To an `http://` proxy and a SOCKS5 one they travel in
 * clear (RFC 7617 section 4, RFC 1929 section 5); to an `https://` proxy ([ResolvedProxy.https]) only inside TLS with
 * the proxy, once its certificate has been verified. [toString] leaves the password out, and [hashCode]
 * depends on the user name only. For SOCKS5 the password must have 1 to 255 bytes in UTF-8: RFC 1929 section 2 gives
 * PASSWD 1 to 255 octets (curl and Go's x/net/proxy send an empty one with PLEN 0, which the RFC does not allow), so a
 * SOCKS5 proxy configured with an empty password fails at once with [IllegalArgumentException] (the engine's creation
 * for its `proxy`, [ResolvedProxy.socks5] for a resolver's). An HTTP proxy takes an empty password (RFC 7617), but not a
 * user name with a colon nor control characters (0x00-0x1F, 0x7F) in either part: RFC 7617 section 2 makes such a
 * user-id invalid and forbids control characters to the sender, so an HTTP, HTTPS or CONNECT-UDP proxy configured with
 * them fails the same way ([ResolvedProxy.http], [ResolvedProxy.https], [ConnectUdpProxy], the engine's `proxy`).
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

    /** Equal when the user and the password are. */
    override fun equals(other: Any?): Boolean = other is ProxyCredentials && other.user == user && other.password == password

    /** Consistent with [equals]. */
    override fun hashCode(): Int = user.hashCode()

    /** For logs; never shows the password. */
    override fun toString(): String = "ProxyCredentials(user=$user, password=***)"
}

@OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
private val nextCredentialsId = kotlin.concurrent.atomics.AtomicLong(0)

/**
 * A proxy refused or failed the request's connection: a SOCKS5 reply other than "succeeded" ([replyCode][ProxyException.replyCode] is its REP
 * field, RFC 1928 section 6), a SOCKS5 authentication the proxy rejected ([replyCode][ProxyException.replyCode] null), a status other than 2xx in
 * answer to an HTTP CONNECT ([replyCode][ProxyException.replyCode] is the status, 407 when the proxy wants credentials; the engine does not
 * repeat the CONNECT), or, as [ProxyTlsException], a failed TLS handshake with an `https://` proxy or a CONNECT-UDP proxy
 * ([ConnectUdpProxy]). The message names the proxy, never the credentials.
 */
@ExperimentalKuicksilverApi
public open class ProxyException(
    message: String,
    /** The SOCKS5 reply code or the HTTP status of the CONNECT response; null when the proxy gave none. */
    public val replyCode: Int?,
    /** What failed underneath, or null. */
    cause: Throwable? = null,
) : IOException(message, cause)

/**
 * The TLS handshake with an `https://` proxy ([ResolvedProxy.https]) or with a CONNECT-UDP proxy ([ConnectUdpProxy], over
 * QUIC) failed: its certificate did not verify against the proxy's name or trust (`KuicksilverEngineConfig.proxyTls`), it
 * refused the handshake, or it closed the connection during it. [cause][Throwable.cause] is what the TLS layer reported: a
 * `TlsException` (its `Verify` subclass says why the certificate was rejected, `AlertReceived` which alert the proxy
 * sent), or, over TCP only, an IOException for a connection that ended; over QUIC it is always a `TlsException`, and a
 * proxy that does not answer ends in the connect timeout instead. Nothing of the request, credentials included, was sent.
 * A TLS failure with the origin inside the proxy's tunnel is the origin's `TlsException`, never this one.
 * [replyCode][ProxyException.replyCode] is null.
 */
@ExperimentalKuicksilverApi
public class ProxyTlsException(
    message: String,
    cause: Throwable,
) : ProxyException(message, null, cause)

/**
 * A proxy as the engine uses it, what a [ProxyResolver] answers: HTTP ([http]: CONNECT tunnels for TLS and WebSockets,
 * the absolute form for plain http), HTTP over TLS to the proxy itself ([https], as curl's HTTPS proxy and Chrome's `HTTPS`
 * PAC entries: the same requests, inside TLS with the proxy) or SOCKS5 ([socks5]: CONNECT only, RFC 1928), with the credentials to present and,
 * for SOCKS5, whether the proxy resolves the origin's name ([remoteDns][ResolvedProxy.remoteDns], `socks5h`) or the engine sends it an address it
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
    /**
     * TLS to the proxy itself ([https]): the engine speaks to the proxy inside TLS, its certificate verified against
     * [host][ResolvedProxy.host] (RFC 9525), before anything of the request goes out; false for [http] and [socks5].
     */
    public val tls: Boolean,
) {
    internal enum class Kind { Http, Socks5 }

    init {
        require(host.isNotEmpty()) { "a proxy needs a host" }
        require(port in 1..0xffff) { "proxy port out of range: $port" }
        credentials?.let { if (kind == Kind.Socks5) requireSocks5Password(it) else requireBasicCredentials(it) }
    }

    /** [ProxyType.HTTP] (with or without [tls][ResolvedProxy.tls]) or [ProxyType.SOCKS] (SOCKS5). */
    public val type: ProxyType get() = if (kind == Kind.Http) ProxyType.HTTP else ProxyType.SOCKS

    /**
     * Part of the connection pool's key: another proxy, its scheme (an `https://` proxy and an `http://` one at the same
     * host and port are two routes), or another [ProxyCredentials] instance is another route. The instance's opaque id
     * stands for the credentials, so nothing derived from the password is kept or compared there.
     */
    internal val routeKey: String get() = "${scheme()}://${uriHost(host)}:$port#${credentials?.id ?: 0}"

    /** `Basic` credentials for `Proxy-Authorization`, when there are credentials. */
    internal val basicAuthorization: String?
        get() = credentials?.let { "Basic " + Base64.encode("${it.user}:${it.password}".encodeToByteArray()) }

    /** Equal when the kind, host, port, credentials, remoteDns and tls flags are. */
    override fun equals(other: Any?): Boolean =
        other is ResolvedProxy && other.kind == kind && other.host == host && other.port == port &&
            other.credentials == credentials && other.remoteDns == remoteDns && other.tls == tls

    /** Consistent with [equals]. */
    override fun hashCode(): Int =
        (((kind.hashCode() * 31 + host.hashCode()) * 31 + port) * 31 + (credentials?.hashCode() ?: 0)) * 31 + tls.hashCode()

    /** For logs: `http://`, `https://`, `socks5://` or `socks5h://`, the host and the port; never the credentials. */
    override fun toString(): String = "${scheme()}://${uriHost(host)}:$port"

    private fun scheme(): String =
        when {
            kind == Kind.Http && tls -> "https"
            kind == Kind.Http -> "http"
            remoteDns -> "socks5h"
            else -> "socks5"
        }

    /** Builds them. */
    public companion object {
        /**
         * An HTTP proxy at [host]:[port], spoken to in plain TCP: its CONNECT and absolute-form requests, and [credentials]
         * with them, cross the network in clear (RFC 7617 section 4); use [https] for a proxy that speaks TLS. Fails with
         * [IllegalArgumentException] for [credentials] that `Basic` cannot carry: a user name with a colon, or control
         * characters in either part (RFC 7617 section 2).
         */
        public fun http(
            host: String,
            port: Int,
            credentials: ProxyCredentials? = null,
        ): ResolvedProxy = ResolvedProxy(Kind.Http, socketHost(host), port, credentials, remoteDns = true, tls = false)

        /**
         * A SOCKS5 proxy at [host]:[port]; [remoteDns][ResolvedProxy.remoteDns] true (`socks5h`) lets it resolve the origin's name. Fails with
         * [IllegalArgumentException] for [credentials] whose password is empty or longer than 255 bytes (RFC 1929
         * section 2: PASSWD has 1 to 255 octets).
         */
        public fun socks5(
            host: String,
            port: Int,
            credentials: ProxyCredentials? = null,
            remoteDns: Boolean = true,
        ): ResolvedProxy = ResolvedProxy(Kind.Socks5, socketHost(host), port, credentials, remoteDns, tls = false)

        /**
         * An HTTPS proxy at [host]:[port]: TLS to the proxy itself (an `https://` proxy URL), then the same requests as
         * [http] inside it, so [credentials] and the CONNECT's target never cross the network in clear. The proxy's
         * certificate is verified against [host] (a DNS name, or an IP address as an IP-ID; RFC 9525), which is also its
         * SNI unless it is an IP address (RFC 6066 section 3), with `KuicksilverEngineConfig.proxyTls` (by default the
         * engine's own trust without the origin's pins and expected name); ALPN offers `http/1.1` only. A request to an
         * `https` origin runs the origin's TLS inside the tunnel (TLS in TLS), verified as without a proxy. [host] goes
         * through the engine's `dns`. [credentials] are checked as for [http].
         */
        public fun https(
            host: String,
            port: Int,
            credentials: ProxyCredentials? = null,
        ): ResolvedProxy = ResolvedProxy(Kind.Http, socketHost(host), port, credentials, remoteDns = true, tls = true)
    }
}

/**
 * Refuses [credentials] whose password RFC 1929 section 2 cannot carry: PASSWD has 1 to 255 octets. curl and Go's
 * x/net/proxy send an empty password as PLEN 0, outside the protocol; a proxy may read that as a malformed request.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun requireSocks5Password(credentials: ProxyCredentials) {
    require(credentials.password.encodeToByteArray().size in 1..255) {
        "a SOCKS5 password has 1 to 255 bytes (RFC 1929 section 2: PASSWD is 1 to 255 octets); an empty one cannot be sent"
    }
}

/**
 * Refuses [credentials] that RFC 7617 section 2 does not let a sender put into `Basic`: "a user-id containing a colon
 * character is invalid" (the recipient splits user-pass at the first colon, so the proxy would read another user and
 * password), and "The user-id and password MUST NOT contain any control characters" (CTL, RFC 5234 appendix B.1:
 * 0x00-0x1F and 0x7F). The message never shows the credentials.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal fun requireBasicCredentials(credentials: ProxyCredentials) {
    require(':' !in credentials.user) { "a user-id for HTTP Basic proxy authentication cannot contain a colon (RFC 7617 section 2)" }
    require(credentials.user.none { isCtl(it) } && credentials.password.none { isCtl(it) }) {
        "the user-id and password for HTTP Basic proxy authentication cannot contain control characters (RFC 7617 section 2)"
    }
}

private fun isCtl(c: Char): Boolean = c < '\u0020' || c == '\u007f'

/**
 * The engine's `proxy` as a [ResolvedProxy], null for `java.net.Proxy.NO_PROXY` (a direct connection). Credentials come from the proxy URL's user info (not on the JVM, whose
 * `ProxyConfig` is a `java.net.Proxy` without them), else [fallback]. An `https://` proxy URL (only expressible off the
 * JVM) is [ResolvedProxy.https]. A type other than HTTP and SOCKS fails with UnsupportedOperationException rather than
 * being bypassed, and so does, on the JVM and Android, an HTTP `java.net.Proxy` on port 443 ([JVM_PROXY_ON_443]): it has no
 * scheme, and Ktor's `ProxyBuilder.http(Url("https://proxy"))` makes exactly that, so speaking plain HTTP to it would send
 * the CONNECT, the origin's name and the credentials in clear to what was meant as an `https://` proxy (CWE-319).
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
    // a NetworkAddress (java.net's on the JVM, ktor-utils' on Native): its address, not a reverse lookup of it
    val address = resolveAddress()
    val credentials = platformProxyCredentials() ?: fallback
    val tls = platformProxyUsesTls()
    // fail closed: a scheme-less HTTP proxy on the https port is most likely an https:// URL whose scheme was lost
    if (kind == ResolvedProxy.Kind.Http && tls == null && address.port == 443) throw UnsupportedOperationException(JVM_PROXY_ON_443)
    return when {
        kind == ResolvedProxy.Kind.Socks5 -> ResolvedProxy.socks5(address.address, address.port, credentials)
        tls == true -> ResolvedProxy.https(address.address, address.port, credentials)
        else -> ResolvedProxy.http(address.address, address.port, credentials)
    }
}

internal const val JVM_PROXY_ON_443: String =
    "an HTTP java.net.Proxy on port 443: a java.net.Proxy has no scheme (ProxyBuilder.http(Url(\"https://...\")) makes one), " +
        "and plain HTTP to an https:// proxy would send the CONNECT and the credentials in clear; for TLS to the proxy use " +
        "proxyResolver = ProxyResolver { ResolvedProxy.https(host, 443, credentials) }, for a plain proxy on 443 use " +
        "ResolvedProxy.http(host, 443, credentials)"

/** The credentials in the proxy URL's user info, percent-decoded; null on the JVM and without user info. */
@OptIn(ExperimentalKuicksilverApi::class)
internal expect fun ProxyConfig.platformProxyCredentials(): ProxyCredentials?

/** Whether this is `java.net.Proxy.NO_PROXY` (only on the JVM). */
internal expect fun ProxyConfig.platformProxyIsDirect(): Boolean

/**
 * Whether the proxy URL is `https://`: TLS to the proxy ([ResolvedProxy.https]); null where the `ProxyConfig` has no scheme
 * to tell (a `java.net.Proxy` on the JVM and Android).
 */
internal expect fun ProxyConfig.platformProxyUsesTls(): Boolean?

/**
 * The proxy for a request to [url]: the engine's explicit `proxy` (with `proxyCredentials`), else what its
 * `proxyResolver` says (cached per route), null for a direct connection. Fails with UnsupportedOperationException for a
 * proxy the engine cannot use, so a request never bypasses it.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal suspend fun KuicksilverEngine.proxyFor(url: io.ktor.http.Url): ResolvedProxy? =
    if (config.proxy == null) proxies.lookup(url) else proxies.explicit()

/**
 * Whether HTTP/3 can go through this proxy: never, today. QUIC is UDP, and neither a CONNECT tunnel (over TCP, to the
 * proxy in clear or in TLS) nor SOCKS5 CONNECT carries it; through a proxy a request uses TCP, and `H3Only` fails. This is
 * the one place the engine asks: CONNECT-UDP (RFC 9298, HTTP/3 proxying of UDP) makes it true for a proxy that offers it,
 * together with an HTTP/3 path that goes through that proxy, never around it.
 */
internal val ResolvedProxy.carriesHttp3: Boolean get() = false
