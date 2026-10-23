// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** A `java.net.Proxy` carries no credentials: `proxyCredentials` supplies them. */
@OptIn(ExperimentalKuicksilverApi::class)
internal actual fun ProxyConfig.platformProxyCredentials(): ProxyCredentials? = null

internal actual fun ProxyConfig.platformProxyIsDirect(): Boolean = type() == java.net.Proxy.Type.DIRECT

/** A `java.net.Proxy` has no scheme: an HTTP one is always reached in plain TCP. */
internal actual fun ProxyConfig.platformProxyUsesTls(): Boolean = false
