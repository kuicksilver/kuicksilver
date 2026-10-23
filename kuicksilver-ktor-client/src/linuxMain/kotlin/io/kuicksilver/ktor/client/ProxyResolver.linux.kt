// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

/** Linux has no system proxy API (desktop settings live in gsettings, which is not read): the environment's. */
internal actual val platformSystemProxyResolver: ProxyResolver = EnvironmentProxyResolver { platformGetenv(it) }
