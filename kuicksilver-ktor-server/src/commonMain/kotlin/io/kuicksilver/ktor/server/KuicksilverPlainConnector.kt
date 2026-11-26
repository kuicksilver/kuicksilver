// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorConfig
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl
import io.kuicksilver.annotations.SecuritySensitive

/**
 * A plain HTTP/1.1 connector, as Ktor's `connector { }`, with [allowMisdirectedHosts][Builder.allowMisdirectedHosts], the
 * PROXY protocol and, opt-in, cleartext HTTP/2 ([h2c][Builder.h2c]): made by `plainConnector { ... }` in the engine
 * configuration. A plain connection is secured by no certificate, so a request whose target is an `https` URI (absolute
 * form, or `:scheme https` over h2c) gets `421 Misdirected Request` (RFC 9110 section 7.4) unless
 * [allowMisdirectedHosts][Builder.allowMisdirectedHosts] is set. When the engine's `tls { }` has an identity, the engine
 * serves this connector with TLS instead (its PROXY protocol and [allowMisdirectedHosts][Builder.allowMisdirectedHosts]
 * kept), as it does Ktor's own connectors.
 */
public class KuicksilverPlainConnector internal constructor(
    /** The host name or address to bind. */
    override val host: String,
    /** The TCP port to bind. */
    override val port: Int,
    /** Whether every client of this connector is a trusted gateway; see [Builder.allowMisdirectedHosts]. */
    internal val allowMisdirectedHosts: Boolean,
    /** Whether this connector serves HTTP/2 over cleartext TCP; see [Builder.h2c]. */
    @property:ExperimentalKuicksilverApi
    internal val h2c: H2cMode,
    /** The PROXY protocol on this connector, or null for none; see [Builder.proxyProtocol]. */
    internal val proxyProtocol: ProxyProtocolConfig?,
    /** Bound to every interface ([Builder.host] null): `::`, or `0.0.0.0` where the host has no IPv6. */
    internal val everyInterface: Boolean = false,
) : EngineConnectorConfig {
    /** Always plain HTTP. */
    override val type: ConnectorType get() = ConnectorType.HTTP

    /** The same connector bound to [port] (resolved connectors report the real port). */
    @OptIn(ExperimentalKuicksilverApi::class)
    internal fun withPort(port: Int): KuicksilverPlainConnector =
        KuicksilverPlainConnector(host, port, allowMisdirectedHosts, h2c, proxyProtocol, everyInterface)

    /** The same connector on [host] (every interface on a host without IPv6: `0.0.0.0`). */
    @OptIn(ExperimentalKuicksilverApi::class)
    internal fun withHost(host: String): KuicksilverPlainConnector =
        KuicksilverPlainConnector(host, port, allowMisdirectedHosts, h2c, proxyProtocol, everyInterface)

    /** For logs. */
    @OptIn(ExperimentalKuicksilverApi::class)
    override fun toString(): String = if (h2c == H2cMode.Off) "HTTP $host:$port" else "HTTP $host:$port (h2c ${h2c.name})"

    /** Builds a [KuicksilverPlainConnector]; used by `plainConnector { ... }` in the engine configuration. */
    @KuicksilverDsl
    public class Builder internal constructor() {
        /**
         * The address to bind; null (the default): every interface, IPv6 and IPv4, with one dual-stack socket bound to `::`
         * (IPv4 clients reach it as IPv4-mapped addresses), or `0.0.0.0` where the host has no IPv6 (logged at Info).
         * `"0.0.0.0"` keeps IPv4 alone. Since 0.3.0 (0.2: `0.0.0.0`).
         */
        public var host: String? = null

        /** The TCP port; 0 picks a free port (see `resolvedConnectors()`); 80 by default. */
        public var port: Int = 80

        /**
         * False by default: a request whose target is in absolute form with the `https` scheme (`GET https://host/ HTTP/1.1`)
         * is answered `421 Misdirected Request` and never reaches the application, since a request for an "https" resource
         * "MUST be rejected unless it has been received over a connection that has been secured via a certificate valid for
         * that target URI's origin" (RFC 9110 section 7.4). Origin-form requests, which a gateway in front of the server
         * sends, are served whatever their `Host`. True accepts such targets (and, when the engine serves this connector
         * with TLS, requests for hosts its certificate does not name): only when every client of this connector is a
         * trusted gateway ("Unless the connection is from a trusted gateway").
         */
        @DelicateKuicksilverApi
        @SecuritySensitive
        public var allowMisdirectedHosts: Boolean = false

        /**
         * HTTP/2 over cleartext TCP with prior knowledge (RFC 9113 section 3.3), [H2cMode.Off] by default:
         * [H2cMode.WithHttp11] serves HTTP/1.1 and h2c on this port, told apart by the client connection preface;
         * [H2cMode.Only] serves h2c alone (ADR-0018). Independent of the engine's `http2 { enabled }` (which is ALPN `h2` on
         * TLS connectors). The engine's `http2 { settings { } }`, limits, flood defences and `webSockets { overHttp2 }` (RFC
         * 8441, `ws://` over h2c) apply as on TLS. Cleartext: only behind a trusted network or proxy (CWE-319;
         * docs/spec/threat-model.md). A connector that the engine turns into a TLS one (an identity in the engine's
         * `tls { }`) cannot take it: the start fails with IllegalArgumentException, since HTTP/2 over TLS "MUST use protocol
         * negotiation in TLS" (section 3.3).
         */
        @ExperimentalKuicksilverApi
        @SecuritySensitive
        public var h2c: H2cMode = H2cMode.Off

        private var proxy: ProxyProtocolConfig? = null

        /**
         * The PROXY protocol (HAProxy, versions 1 and 2) on this connector: every connection must start with a header from
         * one of its trusted sources, which becomes the requests' `origin`; none by default. See [ProxyProtocolConfig].
         *
         * @throws IllegalArgumentException for no or an invalid trusted source, a header timeout below 3 s, or a size out of range.
         */
        @SecuritySensitive
        public fun proxyProtocol(block: ProxyProtocolConfig.Builder.() -> Unit) {
            proxy = ProxyProtocolConfig.Builder().apply(block).build()
        }

        /** The connector; throws [IllegalArgumentException] for a port outside 0..65535. */
        @OptIn(DelicateKuicksilverApi::class, ExperimentalKuicksilverApi::class)
        internal fun build(): KuicksilverPlainConnector {
            require(port in 0..65_535) { "plainConnector { port } must be 0..65535" }
            val h = host
            return KuicksilverPlainConnector(h ?: EVERY_INTERFACE, port, allowMisdirectedHosts, h2c, proxy, h == null)
        }
    }
}
