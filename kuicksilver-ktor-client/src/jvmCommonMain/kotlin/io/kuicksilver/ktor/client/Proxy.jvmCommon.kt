// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** A `java.net.Proxy` carries no credentials: `proxyCredentials` supplies them. */
@OptIn(ExperimentalKuicksilverApi::class)
internal actual fun ProxyConfig.platformProxyCredentials(): ProxyCredentials? = null

internal actual fun ProxyConfig.platformProxyIsDirect(): Boolean = type() == java.net.Proxy.Type.DIRECT

/** A `java.net.Proxy` has no scheme: unknown (an HTTP one on port 443 is refused, `JVM_PROXY_ON_443`). */
internal actual fun ProxyConfig.platformProxyUsesTls(): Boolean? = null
