// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.ClientHelloInfo
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.OcspStapling
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
     * Picks an identity per SNI name, on TCP and HTTP/3 (QUIC) connections alike; see [Builder.sniSelector].
     */
    public val sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)?,
    /**
     * The OCSP response stapled for [identity][KuicksilverTlsConnector.identity] on TCP and QUIC (RFC 9325 section 7.5),
     * null for none; its `update` replaces it while the server runs. See `OcspStapling` for when a response is sent.
     */
    @property:ExperimentalKuicksilverApi public val ocspStapling: OcspStapling?,
    /**
     * Whether every connection to this connector comes from a trusted gateway, the one exception RFC 9110 section 7.4 makes
     * to rejecting misdirected requests; see [Builder.trustedGateway].
     */
    @ExperimentalKuicksilverApi
    public val trustedGateway: Boolean,
    /** The TLS versions of the TCP side; QUIC is always TLS 1.3. See [Builder.versions]. */
    @ExperimentalKuicksilverApi
    public val versions: TlsVersions,
    /** The key-exchange groups of TCP and QUIC, in the server's order of preference. See [Builder.keyExchangeGroups]. */
    @ExperimentalKuicksilverApi
    public val keyExchangeGroups: KeyExchangeGroups,
    /** The PROXY protocol on the TCP side of this connector, or null (the default) for none; see [Builder.proxyProtocol]. */
    @ExperimentalKuicksilverApi
    public val proxyProtocol: ProxyProtocolConfig? = null,
    /** The Encrypted Client Hello keys of TCP and QUIC, or null (the default) for none; see [Builder.echKeys]. */
    @ExperimentalKuicksilverApi
    public val echKeys: EchServerKeys? = null,
) : EngineConnectorConfig {
    /** Always HTTPS. */
    override val type: ConnectorType get() = ConnectorType.HTTPS

    /**
     * The server TLS configuration for [alpn]: with `h3` among them the QUIC one (TLS 1.3 only, RFC 9001 section 4.2), else the
     * TCP one with [versions][KuicksilverTlsConnector.versions] and `alpnFallback = "http/1.1"` (a client without ALPN speaks
     * HTTP/1.1, RFC 9113 section 3.3, and is refused with `no_application_protocol` where the protocols leave it out).
     */
    public fun tlsConfig(alpn: List<String>): TlsConfig = tlsConfig(alpn, null, quic = "h3" in alpn)

    /**
     * [tlsConfig] with the TLS-over-TCP handshake deadline [handshakeTimeout] (null: `TlsConfig`'s default); [quic] keeps it at
     * TLS 1.3 whatever [versions][KuicksilverTlsConnector.versions] says.
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
            sniSelector = this@KuicksilverTlsConnector.sniSelector?.let { if (quic) forHttp3(it) else it }
            ocspStapling = this@KuicksilverTlsConnector.ocspStapling
            keyExchangeGroups = this@KuicksilverTlsConnector.keyExchangeGroups
            echKeys = this@KuicksilverTlsConnector.echKeys
            if (!quic) {
                versions = this@KuicksilverTlsConnector.versions
                // RFC 9113 section 3.3: "HTTP/2 connections over TLS MUST use protocol negotiation in TLS": a client without
                // ALPN speaks HTTP/1.1, refused (no_application_protocol) where the name's protocols leave http/1.1 out
                alpnFallback = HTTP11_ALPN
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
    @OptIn(ExperimentalKuicksilverApi::class)
    public fun withPort(port: Int): KuicksilverTlsConnector =
        KuicksilverTlsConnector(
            host,
            port,
            identity,
            clientAuth,
            trust,
            cipherSuites,
            sniSelector,
            ocspStapling,
            trustedGateway,
            versions,
            keyExchangeGroups,
            proxyProtocol,
            echKeys,
        )

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
         * Picks an identity per SNI name (`TlsConfig.Builder.sniSelector`), on TCP and HTTP/3 connections alike: one
         * selector answers both, so a name gets the same certificate, client-certificate policy and staple over HTTP/1.1,
         * HTTP/2 and HTTP/3, and the `Alt-Svc` the TCP side advertises leads to a QUIC endpoint that presents the same
         * identity. On HTTP/3 it runs off the connection's loop, as on TCP inside the handshake. An answer's `alpn` restricts
         * the name: without one the name gets every protocol of the connector; with one, TCP negotiates from it without
         * `h3` (QUIC only, RFC 9114 section 3.1: a list of `h3` alone ends the name's TCP handshake with
         * `no_application_protocol`; a client without ALPN speaks HTTP/1.1, RFC 9113 section 3.3, refused there when the list
         * leaves `http/1.1` out), and HTTP/3 is served (and advertised with `Alt-Svc` on that name's TCP responses) only
         * when it lists `h3`, else the QUIC handshake ends with `no_application_protocol`. Return the same `TrustConfig` and `OcspStapling` objects for a name,
         * so that its handshakes share one TLS context. Null with SNI present refuses the handshake (`unrecognized_name`); null for a
         * ClientHello without SNI leaves the connector's own [identity][KuicksilverTlsConnector.Builder.identity] to answer it. A request on such a connection must be for the name its identity was chosen
         * for (else 421, RFC 9110 section 7.4). Null by default.
         */
        public var sniSelector: (suspend (ClientHelloInfo) -> ServerTlsOverride?)? = null

        /**
         * The OCSP response to staple (RFC 6066 section 8; docs/guide/tls.md, "Certificate revocation"); null by default.
         * `OcspStapling.update` replaces it while the server runs.
         */
        @ExperimentalKuicksilverApi
        public var ocspStapling: OcspStapling? = null

        /**
         * False by default: a request for an `https` URI whose host the certificate presented on its connection does not name
         * (subjectAltName, as a client checks it) is answered `421 Misdirected Request` and never reaches the application,
         * on HTTP/1.1, HTTP/2 and HTTP/3 alike (RFC 9110 section 7.4; on HTTP/2 and HTTP/3 the connection stays open for
         * other requests). A browser that reuses a connection for another host of the same address sends such requests.
         * True turns the check off for this connector: only when every client of it is a trusted gateway (RFC 9110 section
         * 7.4: "Unless the connection is from a trusted gateway") that forwards requests for names this certificate does
         * not carry, such as a TLS-terminating proxy that re-encrypts with an internal certificate.
         */
        @ExperimentalKuicksilverApi
        public var trustedGateway: Boolean = false

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

        /**
         * The key-exchange groups of TCP and QUIC handshakes, in the server's order of preference (`TlsConfig.Builder.keyExchangeGroups`);
         * default [KeyExchangeGroups.Default]. The server takes the first of them a client sent a key share for, else asks for
         * the first the client supports with a HelloRetryRequest; a client with none of them is refused with `handshake_failure`.
         * Key shares are a client's setting: a list with them makes the server's start fail. With [versions] Tls12And13 the
         * list needs an elliptic curve, the hybrids being TLS 1.3 only, and with [clientAuth] it also limits the curves of a TLS
         * 1.2 client's ECDSA certificate (RFC 8422 section 5.1): without `secp256r1` a P-256 client certificate is refused with
         * `illegal_parameter`.
         */
        @ExperimentalKuicksilverApi
        public var keyExchangeGroups: KeyExchangeGroups = KeyExchangeGroups.Default

        /**
         * The PROXY protocol (HAProxy, versions 1 and 2) on the TCP side of this connector: every TCP connection must start
         * with a header from one of its trusted sources, before the TLS ClientHello, and the client it names becomes the
         * requests' `origin`; null (the default) takes none. HTTP/3 on the same port (QUIC, UDP) takes no header. See
         * [ProxyProtocolConfig].
         */
        @ExperimentalKuicksilverApi
        public var proxyProtocol: ProxyProtocolConfig? = null

        /** Sets [proxyProtocol] from [block]. */
        @ExperimentalKuicksilverApi
        public fun proxyProtocol(block: ProxyProtocolConfig.Builder.() -> Unit) {
            proxyProtocol = ProxyProtocolConfig.Builder().apply(block).build()
        }

        /**
         * The Encrypted Client Hello keys (RFC 9849, shared mode) of TCP and QUIC handshakes alike; default null, which
         * ignores a client's ECH (it is told nothing, and goes on with its outer ClientHello). Publish the keys'
         * ECHConfigList in the `ech` parameter of the HTTPS record of every name this connector serves (RFC 9848).
         * [EchServerKeys.rotate] replaces the keys while the server runs: handshakes that start afterwards use the new
         * set, on TCP and QUIC alike. A client whose ECH is not decrypted (an old key, GREASE) gets the keys' retry
         * configurations and must authenticate this connector's certificate for the configurations' `public_name` (RFC
         * 9849 section 6.1.7): [identity][KuicksilverTlsConnector.Builder.identity] (or what [sniSelector] answers for
         * that name, which it is asked for then) must be valid for it.
         */
        @ExperimentalKuicksilverApi
        public var echKeys: EchServerKeys? = null

        /** The connector; throws [IllegalArgumentException] for a port outside 0..65535. */
        @OptIn(ExperimentalKuicksilverApi::class)
        public fun build(): KuicksilverTlsConnector {
            require(port in 0..65_535) { "port must be 0..65535" }
            return KuicksilverTlsConnector(
                host,
                port,
                identity,
                clientAuth,
                trust,
                cipherSuites,
                sniSelector,
                ocspStapling,
                trustedGateway,
                versions,
                keyExchangeGroups,
                proxyProtocol,
                echKeys,
            )
        }
    }
}
