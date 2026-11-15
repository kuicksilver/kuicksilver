// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/** Session waits that must end with the connection. */
class SessionGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * A client that depends on the server's SETTINGS waits for them: Extended CONNECT (RFC 8441 section 3, which RFC 9220
     * section 3 adopts: "Upon receipt of SETTINGS_ENABLE_CONNECT_PROTOCOL with a value of 1, a client MAY use the Extended
     * CONNECT"). A connection that ends before they arrive ends that wait with the connection's error instead of leaving the
     * caller suspended.
     */
    @Test fun negative_awaitingPeerSettingsEndsWhenTheConnectionCloses() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c) // the raw server never opens its control stream
                val waiting = async { runCatching { client.session.awaitPeerSettings() } }
                s.close(Http3ErrorCode.NO_ERROR, "")
                val r = withTimeout(10.seconds) { waiting.await() }
                assertIs<Http3Exception>(r.exceptionOrNull())
            }
        }
}
