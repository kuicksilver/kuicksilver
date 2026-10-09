// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorConfig
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.ClientHelloInfo
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig

/**
 * A TLS connector on every platform: HTTP/1.1 over TLS on TCP and, unless turned off, HTTP/3 on UDP on the
 * same port. [clientAuth] `Optional` asks for a client certificate without requiring one; [trust] verifies it.
 */
public class KuicksilverTlsConnector private constructor(
    override val host: String,
    override val port: Int,
    /** The server certificate chain and key, shared by TCP and QUIC. */
    public val identity: TlsIdentity,
    /** Whether a client certificate is asked for ([ClientAuth.Optional]) or required ([ClientAuth.Required]). */
    public val clientAuth: ClientAuth,
    /** Verifies client certificates (`TrustConfig.AnchoredCa`, optionally pinned); needed unless [clientAuth] is None. */
    public val trust: TrustConfig?,
    /** The TLS 1.3 cipher suites in preference order. */
    public val cipherSuites: CipherSuites,
    /**
     * Picks an identity per SNI name on TCP connections; QUIC cannot use it, so with HTTP/3 on a connector that sets it
     * fails to start with `TlsException.Config`.
     */
    public val sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)?,
) : EngineConnectorConfig {
    override val type: ConnectorType get() = ConnectorType.HTTPS

    /** The server TLS configuration for [alpn] (`http/1.1` on TCP, `h3` on QUIC). */
    public fun tlsConfig(alpn: List<String>): TlsConfig =
        tlsConfig(TlsRole.Server) {
            this.alpn = alpn
            identity = this@KuicksilverTlsConnector.identity
            clientAuth = this@KuicksilverTlsConnector.clientAuth
            this@KuicksilverTlsConnector.trust?.let { trust = it }
            cipherSuites = this@KuicksilverTlsConnector.cipherSuites
            sniSelector = this@KuicksilverTlsConnector.sniSelector
        }

    /** The same connector bound to [port] (resolved connectors report the real port). */
    public fun withPort(port: Int): KuicksilverTlsConnector =
        KuicksilverTlsConnector(host, port, identity, clientAuth, trust, cipherSuites, sniSelector)

    override fun toString(): String = "HTTPS (Kuicksilver TLS) $host:$port"

    /**
     * Builds a [KuicksilverTlsConnector]; used by `tlsConnector(identity) { ... }` in the engine configuration.
     *
     * @property identity the server certificate chain and key, shared by TCP and QUIC.
     */
    @KuicksilverDsl
    public class Builder(
        public var identity: TlsIdentity,
    ) {
        /** The address to bind, for TCP and UDP alike; `0.0.0.0` (every IPv4 interface) by default. */
        public var host: String = "0.0.0.0"

        /** The TCP port, and the UDP port of HTTP/3; 0 picks a free port (see `resolvedConnectors()`); 443 by default. */
        public var port: Int = 443

        /** Ask for ([ClientAuth.Optional]) or require ([ClientAuth.Required]) a client certificate; [ClientAuth.None] by default. */
        public var clientAuth: ClientAuth = ClientAuth.None

        /** Verifies client certificates; required with [clientAuth] other than None. */
        public var trust: TrustConfig? = null

        /** The TLS 1.3 cipher suites in preference order; AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 by default. */
        public var cipherSuites: CipherSuites = CipherSuites.Default

        /** Picks an identity per SNI name (TCP connections). */
        public var sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)? = null

        /** The connector; throws [IllegalArgumentException] for a port outside 0..65535. */
        public fun build(): KuicksilverTlsConnector {
            require(port in 0..65_535) { "port must be 0..65535" }
            return KuicksilverTlsConnector(host, port, identity, clientAuth, trust, cipherSuites, sniSelector)
        }
    }
}
