// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.EngineConnectorConfig

/** On Android the engine takes `tlsConnector(identity)`; `sslConnector {}` is a JVM-server convenience. */
internal actual fun platformTlsConnector(c: EngineConnectorConfig): KuicksilverTlsConnector? = null
