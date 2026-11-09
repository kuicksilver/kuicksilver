// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.utils.io.ByteChannel
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ServerFixturesTest {
    /**
     * A read channel that failed before the read started (a TLS session the server ended with an alert, its failure recorded
     * while the client was still writing): ktor's `readAvailable` answers -1 for it as for a clean end, so [rawHttp] took a
     * refused handshake for an empty response. The read throws the failure instead.
     */
    @Test fun negative_aChannelThatFailedBeforeTheReadThrows() =
        serverTest {
            val r = ByteChannel()
            r.cancel(IOException("certificate_required (116)"))
            val e = assertFailsWith<Throwable> { r.readOrFail(ByteArray(16)) }
            val messages = generateSequence(e) { it.cause }.mapNotNull { it.message }.joinToString()
            assertTrue("certificate_required (116)" in messages, e.toString())
        }

    @Test fun aCleanEndIsMinusOne() =
        serverTest {
            val r = ByteChannel()
            r.flushAndClose()
            assertEquals(-1, r.readOrFail(ByteArray(16)))
        }
}
