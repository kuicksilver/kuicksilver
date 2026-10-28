// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Whether an idle pooled HTTP/1.1 connection may carry the next request. */
class H1IdleConnectionTest {
    /** An idle connection of the pool on [wire], route "r". */
    private suspend fun idle(wire: Wire): Pair<ConnectionPool<H1Connection>, H1Connection> {
        val pool = ConnectionPool<H1Connection>(KuicksilverEngineConfig().poolLimits()) { 0L }
        assertNull(pool.acquire("r"))
        val conn = H1Connection(NoSocket(wire), null, wire.fromServer, wire.toServer, "r")
        pool.adopt(conn)
        assertTrue(pool.release(conn))
        return pool to conn
    }

    /**
     * A server that answers nothing in particular on an idle keep-alive connection (`408 Request Timeout` and a close, RFC
     * 9110 section 15.5.9) leaves bytes no request asked for: the connection is not reused, and the next request gets a
     * fresh one (RFC 9112 section 9.2: the client MUST NOT consider such data a valid response, and SHOULD close the
     * connection). Before, the 408 was read as the answer to that request.
     */
    @Test fun unsolicitedResponseOnIdleConnectionIsNotReused() =
        runTest {
            val wire = Wire()
            val (pool, conn) = idle(wire)
            wire.fromServer.writeStringUtf8("HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
            wire.fromServer.flushAndClose()
            assertNull(pool.acquire("r"), "the connection with the stale 408 was handed out")
            assertTrue(conn.closed)
        }

    /** Unsolicited bytes on a connection the server keeps open make it unusable as well. */
    @Test fun strayBytesOnIdleConnectionAreNotReused() =
        runTest {
            val wire = Wire()
            val (pool, conn) = idle(wire)
            wire.fromServer.writeStringUtf8("x")
            wire.fromServer.flush()
            assertNull(pool.acquire("r"))
            assertTrue(conn.closed)
        }

    /** An idle connection with nothing to read is reused. */
    @Test fun quietIdleConnectionIsReused() =
        runTest {
            val wire = Wire()
            val (pool, conn) = idle(wire)
            assertSame(conn, pool.acquire("r"))
            assertEquals(false, conn.closed)
        }
}
