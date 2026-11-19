// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyConfig
import io.kuicksilver.annotations.ExperimentalKuicksilverApi

/**
 * The proxy URL's user info, percent-decoded (`http://user:pass@proxy:3128`). A broken escape cannot get here (Ktor's
 * `Url` decodes the user info when it is built and fails there); should it, [decodeUserInfo] fails without repeating it.
 */
@OptIn(ExperimentalKuicksilverApi::class)
internal actual fun ProxyConfig.platformProxyCredentials(): ProxyCredentials? =
    url.encodedUser?.takeIf { it.isNotEmpty() }?.let {
        ProxyCredentials(
            decodeUserInfo(it),
            url.encodedPassword?.let(::decodeUserInfo) ?: "",
        )
    }

internal actual fun ProxyConfig.platformProxyIsDirect(): Boolean = false

internal actual fun ProxyConfig.platformProxyUsesTls(): Boolean? = url.protocol.name.equals("https", ignoreCase = true)
