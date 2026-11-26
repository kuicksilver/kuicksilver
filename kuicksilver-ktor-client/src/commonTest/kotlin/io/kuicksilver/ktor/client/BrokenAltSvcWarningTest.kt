// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.ktor.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The engine warns once when it first marks an HTTP/3 alternative broken on a network (ADR-0026): [BrokenAltSvc.markBroken]
 * hands back the backoff for that first mark only, until the network changes or every mark is cleared.
 */
class BrokenAltSvcWarningTest {
    private var now = 1_000_000L
    private val broken = BrokenAltSvc({ now })

    @Test fun onlyTheFirstMarkOnANetworkIsReported() {
        assertEquals(5 * 60_000L, broken.markBroken("a.test:443", "a.test:443", FallbackReason.HandshakeTimeout))
        assertNull(broken.markBroken("b.test:443", "b.test:443", FallbackReason.Other), "another origin on the same network")
        assertNull(broken.markBroken("a.test:443", "a.test:443", FallbackReason.Other), "the same alternative again")
        broken.onNetworkChanged()
        assertEquals(5 * 60_000L, broken.markBroken("b.test:443", "b.test:443", FallbackReason.Other), "a new network warns again")
        broken.clear(null)
        assertEquals(5 * 60_000L, broken.markBroken("c.test:443", "c.test:443", FallbackReason.Other), "after clearing every mark")
        broken.clear("c.test:443")
        assertNull(broken.markBroken("d.test:443", "d.test:443", FallbackReason.Other), "clearing one origin keeps the network's warning")
    }
}
