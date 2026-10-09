// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.EngineConnectorConfig

/** Ktor has no `EngineSSLConnectorConfig` outside the JVM: TLS connectors are `tlsConnector(identity)` here. */
internal actual fun platformTlsConnector(c: EngineConnectorConfig): KuicksilverTlsConnector? = null
