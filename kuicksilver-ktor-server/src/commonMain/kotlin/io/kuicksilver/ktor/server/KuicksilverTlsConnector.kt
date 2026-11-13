// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.ClientHelloInfo
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import io.kuicksilver.tls.tlsConfig
import kotlin.time.Duration

/**
 * A TLS connector on every platform: HTTP/1.1 over TLS on TCP and, unless turned off, HTTP/3 on UDP on the
 * same port. [clientAuth][KuicksilverTlsConnector.clientAuth] `Optional` asks for a client certificate without requiring one; [trust][KuicksilverTlsConnector.trust] verifies it.
 */
public class KuicksilverTlsConnector private constructor(
    /** The host name or address to bind. */
    override val host: String,
    /** The port to bind, shared by TCP and QUIC. */
    override val port: Int,
    /**
     * The server certificate chain and key, shared by TCP and QUIC. A `TlsIdentity.Reloadable` replaces them at run time:
     * each new handshake on either takes the identity current when its ClientHello arrives, running connections keep theirs.
     */
    public val identity: TlsIdentity,
    /** Whether a client certificate is asked for ([ClientAuth.Optional]) or required ([ClientAuth.Required]). */
    public val clientAuth: ClientAuth,
    /**
     * Verifies client certificates (`TrustConfig.AnchoredCa`, optionally pinned); needed unless [clientAuth][KuicksilverTlsConnector.clientAuth] is None.
     * A `TrustConfig.ReloadableCa` replaces the CA bundle at run time: once `reload` returns, no handshake on TCP or QUIC
     * accepts a certificate only a removed CA vouches for; running connections keep going.
     */
    public val trust: TrustConfig?,
    /** The TLS 1.3 cipher suites in preference order. */
    public val cipherSuites: CipherSuites,
    /**
     * Picks an identity per SNI name on TCP connections. QUIC cannot use it in v1, so HTTP/3 is skipped for this
     * connector with a warning: it serves HTTP/1.1 only and sends no `Alt-Svc`.
     */
    public val sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)?,
    /** The TLS versions of the TCP side; QUIC is always TLS 1.3. See [Builder.versions]. */
    @ExperimentalKuicksilverApi
    public val versions: TlsVersions,
) : EngineConnectorConfig {
    /** Always HTTPS. */
    override val type: ConnectorType get() = ConnectorType.HTTPS

    /**
     * The server TLS configuration for [alpn]: with `h3` among them the QUIC one (TLS 1.3 only, RFC 9001 section 4.2), else the
     * TCP one with [versions].
     */
    public fun tlsConfig(alpn: List<String>): TlsConfig = tlsConfig(alpn, null, quic = "h3" in alpn)

    /**
     * [tlsConfig] with the TLS-over-TCP handshake deadline [handshakeTimeout] (null: `TlsConfig`'s default); [quic] keeps it at
     * TLS 1.3 whatever [versions] says.
     */
    @OptIn(ExperimentalKuicksilverApi::class)
    internal fun tlsConfig(
        alpn: List<String>,
        handshakeTimeout: Duration?,
        quic: Boolean,
    ): TlsConfig =
        tlsConfig(TlsRole.Server) {
            handshakeTimeout?.let { this.handshakeTimeout = it }
            this.alpn = alpn
            identity = this@KuicksilverTlsConnector.identity
            clientAuth = this@KuicksilverTlsConnector.clientAuth
            this@KuicksilverTlsConnector.trust?.let { trust = it }
            cipherSuites = this@KuicksilverTlsConnector.cipherSuites
            sniSelector = this@KuicksilverTlsConnector.sniSelector
            if (!quic) versions = this@KuicksilverTlsConnector.versions
        }

    /** The same connector bound to [port] (resolved connectors report the real port). */
    @OptIn(ExperimentalKuicksilverApi::class)
    public fun withPort(port: Int): KuicksilverTlsConnector =
        KuicksilverTlsConnector(host, port, identity, clientAuth, trust, cipherSuites, sniSelector, versions)

    /** For logs. */
    override fun toString(): String = "HTTPS (Kuicksilver TLS) $host:$port"

    /**
     * Builds a [KuicksilverTlsConnector]; used by `tlsConnector(identity) { ... }` in the engine configuration.
     *
     * @property identity the server certificate chain and key, shared by TCP and QUIC; a `TlsIdentity.Reloadable` can be
     *   replaced while the server runs (docs/guide/ktor.md, "Certificate rotation").
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

        /**
         * Verifies client certificates; required with [clientAuth] other than None. A `TrustConfig.ReloadableCa` can be
         * replaced while the server runs (docs/guide/tls.md, "Rotating the client CA").
         */
        public var trust: TrustConfig? = null

        /** The TLS 1.3 cipher suites in preference order; AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 by default. */
        public var cipherSuites: CipherSuites = CipherSuites.Default

        /**
         * Picks an identity per SNI name (TCP connections). HTTP/3 is skipped for this connector with a warning: QUIC
         * cannot pick an identity per SNI name in v1.
         */
        public var sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)? = null

        /**
         * The TLS versions TCP connections may negotiate: [TlsVersions.Tls13] (the default) refuses a client without TLS 1.3
         * with a `protocol_version` alert (RFC 9846 appendix E.2); [TlsVersions.Tls12And13] also serves TLS 1.2 clients (RFC
         * 9325 section 3.1.1: "Implementations MUST support TLS 1.2"), and a client that offers TLS 1.3 still gets it. TLS 1.2
         * runs under the RFC 9325 profile: ECDHE with AES-GCM or ChaCha20-Poly1305 only (no static RSA, no CBC, no SHA-1 MAC),
         * Extended Master Secret required, no renegotiation, no compression; a TLS 1.2 session resumes for at most
         * [SessionTicketConfig.ticketLifetime][io.kuicksilver.tls.SessionTicketConfig.ticketLifetime] after its full handshake,
         * however often its ticket is renewed (at most half a
         * [rotateEvery][io.kuicksilver.tls.SessionTicketConfig.rotateEvery] period; explicit ticket keys are rotated by the
         * application, which then keeps that period itself). HTTP/2 (when on) is offered over TLS 1.2 as well (RFC 9113
         * section 9.2); with a certificate without an rsaEncryption key (an EC or an RSA-PSS one) the start logs a warning, since RFC 9113 section 9.2.2 asks
         * such deployments to support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256. HTTP/3 stays TLS 1.3 (RFC 9001 section 4.2).
         */
        @ExperimentalKuicksilverApi
        public var versions: TlsVersions = TlsVersions.Tls13

        /** The connector; throws [IllegalArgumentException] for a port outside 0..65535. */
        @OptIn(ExperimentalKuicksilverApi::class)
        public fun build(): KuicksilverTlsConnector {
            require(port in 0..65_535) { "port must be 0..65535" }
            return KuicksilverTlsConnector(host, port, identity, clientAuth, trust, cipherSuites, sniSelector, versions)
        }
    }
}
