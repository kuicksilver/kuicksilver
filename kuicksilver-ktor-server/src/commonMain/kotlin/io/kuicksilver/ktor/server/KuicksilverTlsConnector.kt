// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorConfig
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive
import io.kuicksilver.tls.ClientHelloInfo
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.tlsConfig
import kotlin.time.Duration

/**
 * A TLS connector on every platform: HTTP/1.1 (and HTTP/2 with `http2 { enabled }`) over TLS on TCP and, unless turned off,
 * HTTP/3 on UDP on the same port; made by `tlsConnector { }` in the engine configuration. Its TLS is the engine's
 * `tls { }` with the connector's own `tls { }` on top.
 */
public class KuicksilverTlsConnector internal constructor(
    /** The host name or address to bind. */
    override val host: String,
    /** The port to bind, shared by TCP and QUIC. */
    override val port: Int,
    /** The connector's `tls { }` blocks, applied over the engine's `tls { }` when the engine starts. */
    internal val tlsBlocks: List<ServerTlsConfig.() -> Unit>,
    /** The PROXY protocol on the TCP side of this connector, or null for none. */
    internal val proxyProtocol: ProxyProtocolConfig?,
    /** Whether every connection to this connector comes from a trusted gateway (RFC 9110 section 7.4); see [Builder.allowMisdirectedHosts]. */
    internal val allowMisdirectedHosts: Boolean,
    /** The TLS as served, once the engine resolved it ([resolved]); null before. */
    private val resolvedTls: ResolvedServerTls?,
    /** Bound to every interface ([Builder.host] null): `::`, or `0.0.0.0` where the host has no IPv6. */
    internal val everyInterface: Boolean = false,
) : EngineConnectorConfig {
    /** Always HTTPS. */
    override val type: ConnectorType get() = ConnectorType.HTTPS

    /** The TLS this connector serves; only on a connector the engine resolved. */
    internal val tls: ResolvedServerTls get() = checkNotNull(resolvedTls) { "$this was not resolved by the engine" }

    internal val identity: TlsIdentity? get() = tls.identity
    internal val sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)? get() = tls.sniSelector
    internal val versions: TlsVersions get() = tls.versions

    /** This connector with its TLS resolved over [base], the engine's. */
    internal fun resolved(base: ResolvedServerTls): KuicksilverTlsConnector {
        val r =
            if (tlsBlocks.isEmpty()) {
                base
            } else {
                ServerTlsConfig()
                    .apply {
                        inherit(base)
                        tlsBlocks.forEach { it() }
                    }.resolve("tlsConnector { tls")
            }
        require(r.identity != null || r.sniSelector != null) {
            "tlsConnector { } on port $port needs an identity: tls { pemFiles(...) } or tls { identity }, in the engine or " +
                "in the connector (or an sniSelector)"
        }
        return KuicksilverTlsConnector(host, port, tlsBlocks, proxyProtocol, allowMisdirectedHosts, r, everyInterface)
    }

    /**
     * The server TLS configuration for [alpn]: with `h3` among them the QUIC one (TLS 1.3 only, RFC 9001 section 4.2), else the
     * TCP one with the connector's versions and `expert { alpnFallback = "http/1.1" }` (a client without ALPN speaks
     * HTTP/1.1, RFC 9113 section 3.3, and is refused with `no_application_protocol` where the protocols leave it out).
     */
    internal fun tlsConfig(alpn: List<String>): TlsConfig = tlsConfig(alpn, null, quic = "h3" in alpn)

    /**
     * [tlsConfig] with the TLS-over-TCP handshake deadline [handshakeTimeout] (null: `TlsConfig`'s default); [quic] keeps it at
     * TLS 1.3 whatever the connector's versions say.
     */
    @OptIn(DelicateKuicksilverApi::class)
    internal fun tlsConfig(
        alpn: List<String>,
        handshakeTimeout: Duration?,
        quic: Boolean,
    ): TlsConfig {
        val t = tls
        return tlsConfig(TlsRole.Server) {
            handshakeTimeout?.let { this.handshakeTimeout = it }
            this.alpn = alpn
            identity = t.identity
            clientAuth = t.clientAuth
            t.trust?.let { trust = it }
            cipherSuites = t.cipherSuites
            sniSelector = t.sniSelector?.let { if (quic) forHttp3(it) else it }
            ocspStapling = t.ocspStapling
            keyExchangeGroups = t.keyExchangeGroups
            sessionTickets = t.sessionTickets
            keylog = t.keylog
            ech { keys = t.echKeys }
            if (!quic) {
                versions = t.versions
                // RFC 9113 section 3.3: "HTTP/2 connections over TLS MUST use protocol negotiation in TLS": a client without
                // ALPN speaks HTTP/1.1, refused (no_application_protocol) where the name's protocols leave http/1.1 out
                expert { alpnFallback = HTTP11_ALPN }
            }
        }
    }

    /**
     * [selector] for the HTTP/3 side. An answer without an ALPN list keeps the connector's (`h3`); one whose list names `h3`
     * gets `h3` (the rest of the list is for TCP); one whose list leaves `h3` out keeps that list, which a client of HTTP/3
     * shares nothing with, so its QUIC handshake ends with `no_application_protocol` (RFC 7301 section 3.2; CRYPTO_ERROR
     * 0x178): the operator restricted that name to the protocols listed.
     */
    private fun forHttp3(selector: suspend (ClientHelloInfo) -> ServerTlsOverride?): suspend (ClientHelloInfo) -> ServerTlsOverride? =
        { hello ->
            selector(hello)?.let { o ->
                val alpn = o.alpn
                if (alpn == null || "h3" !in alpn) {
                    o
                } else {
                    ServerTlsOverride(o.identity, null, o.clientAuth, o.trust, o.ocspStapling, o.keyExchangeGroups)
                }
            }
        }

    /** The same connector bound to [port] (resolved connectors report the real port). */
    internal fun withPort(port: Int): KuicksilverTlsConnector =
        KuicksilverTlsConnector(host, port, tlsBlocks, proxyProtocol, allowMisdirectedHosts, resolvedTls, everyInterface)

    /** The same connector on [host] (every interface on a host without IPv6: `0.0.0.0`). */
    internal fun withHost(host: String): KuicksilverTlsConnector =
        KuicksilverTlsConnector(host, port, tlsBlocks, proxyProtocol, allowMisdirectedHosts, resolvedTls, everyInterface)

    /** For logs. */
    override fun toString(): String = "HTTPS (Kuicksilver TLS) $host:$port"

    /** Builds a [KuicksilverTlsConnector]; used by `tlsConnector { ... }` in the engine configuration. */
    @KuicksilverDsl
    public class Builder internal constructor() {
        /**
         * The address to bind, for TCP and UDP alike; null (the default): every interface, IPv6 and IPv4, with one dual-stack
         * socket per protocol bound to `::` (an IPv4 client reaches it as an IPv4-mapped address, which `call.request.local`
         * reports as the IPv4 address it is), or `0.0.0.0` where the host has no IPv6 (logged at Info). `"0.0.0.0"` keeps IPv4 alone, `"::1"` or `"127.0.0.1"` one loopback. Since 0.3.0
         * (0.2: `0.0.0.0`).
         */
        public var host: String? = null

        /** The TCP port, and the UDP port of HTTP/3; 0 picks a free port (see `resolvedConnectors()`); 443 by default. */
        public var port: Int = 443

        private val tlsBlocks = ArrayList<ServerTlsConfig.() -> Unit>()

        /**
         * Overrides of the engine's `tls { }` for this connector only: another identity on another port, client certificates
         * on one port, say. What the block does not set is the engine's; an identity or a trust set here replaces the
         * engine's, whichever way either was given. Applied when the engine starts.
         */
        public fun tls(block: ServerTlsConfig.() -> Unit) {
            tlsBlocks += block
        }

        private var proxy: ProxyProtocolConfig? = null

        /**
         * The PROXY protocol (HAProxy, versions 1 and 2) on the TCP side of this connector: every TCP connection must start
         * with a header from one of its trusted sources, before the TLS ClientHello, and the client it names becomes the
         * requests' `origin`; none by default. HTTP/3 on the same port (QUIC, UDP) takes no header. See [ProxyProtocolConfig].
         *
         * @throws IllegalArgumentException for no or an invalid trusted source, a header timeout below 3 s, or a size out of range.
         */
        @SecuritySensitive
        public fun proxyProtocol(block: ProxyProtocolConfig.Builder.() -> Unit) {
            proxy = ProxyProtocolConfig.Builder().apply(block).build()
        }

        /**
         * False by default: a request for an `https` URI whose host the certificate presented on its connection does not name
         * (subjectAltName, as a client checks it) is answered `421 Misdirected Request` and never reaches the application,
         * on HTTP/1.1, HTTP/2 and HTTP/3 alike (RFC 9110 section 7.4; on HTTP/2 and HTTP/3 the connection stays open for
         * other requests). A browser that reuses a connection for another host of the same address sends such requests.
         * True turns the check off for this connector: only when every client of it is a trusted gateway (RFC 9110 section
         * 7.4: "Unless the connection is from a trusted gateway") that forwards requests for names this certificate does
         * not carry, such as a TLS-terminating proxy that re-encrypts with an internal certificate.
         */
        @DelicateKuicksilverApi
        @SecuritySensitive
        public var allowMisdirectedHosts: Boolean = false

        /** The connector; throws [IllegalArgumentException] for a port outside 0..65535. */
        @OptIn(DelicateKuicksilverApi::class)
        internal fun build(): KuicksilverTlsConnector {
            require(port in 0..65_535) { "tlsConnector { port } must be 0..65535" }
            val h = host
            return KuicksilverTlsConnector(h ?: EVERY_INTERFACE, port, tlsBlocks.toList(), proxy, allowMisdirectedHosts, null, h == null)
        }
    }
}

/** What a connector without a host binds: the IPv6 unspecified address, a dual-stack socket. */
internal const val EVERY_INTERFACE: String = "::"

/** What it binds on a host without IPv6. */
internal const val IPV4_EVERY_INTERFACE: String = "0.0.0.0"
