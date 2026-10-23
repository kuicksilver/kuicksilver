// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyConfig
import io.ktor.http.decodeURLPart
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/** The proxy URL's user info, percent-decoded (`http://user:pass@proxy:3128`). */
@OptIn(ExperimentalKuicksilverApi::class)
internal actual fun ProxyConfig.platformProxyCredentials(): ProxyCredentials? =
    url.encodedUser?.takeIf { it.isNotEmpty() }?.let { ProxyCredentials(it.decodeURLPart(), url.encodedPassword?.decodeURLPart() ?: "") }

internal actual fun ProxyConfig.platformProxyIsDirect(): Boolean = false

internal actual fun ProxyConfig.platformProxyUsesTls(): Boolean = url.protocol.name.equals("https", ignoreCase = true)
