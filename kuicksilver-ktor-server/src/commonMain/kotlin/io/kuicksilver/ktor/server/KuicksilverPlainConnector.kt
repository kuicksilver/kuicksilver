// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.KuicksilverDsl

/**
 * A plain HTTP/1.1 connector, as Ktor's `connector { }`, with [trustedGateway]: made by `plainConnector { ... }` in the
 * engine configuration. A plain connection is secured by no certificate, so a request whose absolute-form target is an
 * `https` URI gets `421 Misdirected Request` (RFC 9110 section 7.4) unless [trustedGateway] is set.
 */
@ExperimentalKuicksilverApi
public class KuicksilverPlainConnector private constructor(
    /** The host name or address to bind. */
    override val host: String,
    /** The TCP port to bind. */
    override val port: Int,
    /** Whether every client of this connector is a trusted gateway; see [Builder.trustedGateway]. */
    public val trustedGateway: Boolean,
) : EngineConnectorConfig {
    /** Always plain HTTP. */
    override val type: ConnectorType get() = ConnectorType.HTTP

    /** The same connector bound to [port] (resolved connectors report the real port). */
    public fun withPort(port: Int): KuicksilverPlainConnector = KuicksilverPlainConnector(host, port, trustedGateway)

    /** For logs. */
    override fun toString(): String = "HTTP $host:$port"

    /** Builds a [KuicksilverPlainConnector]; used by `plainConnector { ... }` in the engine configuration. */
    @KuicksilverDsl
    public class Builder {
        /** The address to bind; `0.0.0.0` (every IPv4 interface) by default. */
        public var host: String = "0.0.0.0"

        /** The TCP port; 0 picks a free port (see `resolvedConnectors()`); 80 by default. */
        public var port: Int = 80

        /**
         * False by default: a request whose target is in absolute form with the `https` scheme (`GET https://host/ HTTP/1.1`)
         * is answered `421 Misdirected Request` and never reaches the application, since a request for an "https" resource
         * "MUST be rejected unless it has been received over a connection that has been secured via a certificate valid for
         * that target URI's origin" (RFC 9110 section 7.4). Origin-form requests, which a gateway in front of the server
         * sends, are served whatever their `Host`. True accepts such targets: only when every client of this connector is a
         * trusted gateway ("Unless the connection is from a trusted gateway").
         */
        public var trustedGateway: Boolean = false

        /** The connector; throws [IllegalArgumentException] for a port outside 0..65535. */
        public fun build(): KuicksilverPlainConnector {
            require(port in 0..65_535) { "port must be 0..65535" }
            return KuicksilverPlainConnector(host, port, trustedGateway)
        }
    }
}
