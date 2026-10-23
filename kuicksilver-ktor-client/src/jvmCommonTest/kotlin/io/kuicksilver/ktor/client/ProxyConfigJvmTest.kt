// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import java.net.Proxy
import kotlin.test.Test
import kotlin.test.assertNull

class ProxyConfigJvmTest {
    /** `Proxy.NO_PROXY` as the engine's `proxy` means a direct connection, not an unsupported proxy type. */
    @Test fun noProxyIsDirect() = assertNull(Proxy.NO_PROXY.toResolvedProxy(null))
}
