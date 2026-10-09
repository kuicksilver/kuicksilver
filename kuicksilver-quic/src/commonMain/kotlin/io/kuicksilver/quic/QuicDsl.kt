// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.kuicksilver.tls.TlsConfig

/** Builds a [QuicClientConfig] for [tls] (a client `TlsConfig` QUIC can use); `quic` defaults to [QuicConfig.Default]. */
public inline fun quicClientConfig(
    tls: TlsConfig,
    block: QuicClientConfig.Builder.() -> Unit = {},
): QuicClientConfig = QuicClientConfig.Builder(tls).apply(block).build()

/** Builds a [QuicServerConfig] for [tls] (a server `TlsConfig` QUIC can use); `quic` defaults to [QuicConfig.Default]. */
public inline fun quicServerConfig(
    tls: TlsConfig,
    block: QuicServerConfig.Builder.() -> Unit = {},
): QuicServerConfig = QuicServerConfig.Builder(tls).apply(block).build()

/** Builds a [QuicEndpointConfig] from the defaults; set `server` for an endpoint that accepts connections. */
public inline fun quicEndpointConfig(block: QuicEndpointConfig.Builder.() -> Unit): QuicEndpointConfig =
    QuicEndpointConfig.Builder().apply(block).build()
