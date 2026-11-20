// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.testing.sentinel.LeakSentinel
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds

/**
 * The leak sentinel on a real endpoint (docs/process.md, "The leak sentinel"): an endpoint a test leaves open is named, with
 * its socket; once it is closed, nothing is left. The endpoint is closed before the test ends, so the test itself leaks
 * nothing.
 */
class LeakSentinelEndpointTest {
    @Test fun negative_anEndpointLeftOpenIsNamed() =
        runBlocking {
            val scope = LeakSentinel.begin()
            val endpoint = QuicEndpoint.bind(InetSocketAddress("127.0.0.1", 0))
            try {
                val leak = assertNotNull(LeakSentinel.end(scope, "C", "t", allow = emptyList(), wait = 200.milliseconds))
                assertContains(leak, "quic.endpoint x1")
            } finally {
                endpoint.closeAndJoin()
            }
            assertNull(LeakSentinel.end(scope, "C", "t", allow = emptyList()), "a closed endpoint leaves nothing")
        }
}
