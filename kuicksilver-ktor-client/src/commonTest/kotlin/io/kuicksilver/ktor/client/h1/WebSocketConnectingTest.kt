// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The CONNECTING keys of RFC 6455 section 4.1, step 2, on their own. */
class WebSocketConnectingTest {
    /** WebSockets to distinct remote hosts do not wait for each other. */
    @Test fun distinctHostsDoNotWait() =
        runTest {
            val c = WebSocketConnecting()
            val a = c.acquire(listOf("address 127.0.0.1"))
            val b = c.acquire(listOf("address 127.0.0.2"))
            assertEquals(2, c.size())
            a.release()
            b.release()
            assertEquals(0, c.size())
        }

    /** A second WebSocket that shares one key waits until the first releases; a second release changes nothing. */
    @Test fun sharedHostWaitsForTheRelease() =
        runTest {
            val c = WebSocketConnecting()
            val first = c.acquire(listOf("address 127.0.0.2", "address 127.0.0.1"))
            var secondHeld = false
            val second =
                launch(start = CoroutineStart.UNDISPATCHED) {
                    val h = c.acquire(listOf("address 127.0.0.1"))
                    secondHeld = true
                    h.release()
                }
            assertFalse(secondHeld)
            first.release()
            first.release()
            second.join()
            assertTrue(secondHeld)
            assertEquals(0, c.size())
        }

    /** A WebSocket cancelled while it waits holds nothing afterwards, and its entry goes with the last user. */
    @Test fun cancelledWaiterHoldsNothing() =
        runTest {
            val c = WebSocketConnecting()
            val first = c.acquire(listOf("address 127.0.0.1", "address 127.0.0.2"))
            val waiter = launch(start = CoroutineStart.UNDISPATCHED) { c.acquire(listOf("address 127.0.0.2", "address 127.0.0.3")) }
            waiter.cancel()
            waiter.join()
            assertEquals(2, c.size())
            first.release()
            assertEquals(0, c.size())
            c.acquire(listOf("address 127.0.0.3")).release()
            assertEquals(0, c.size())
        }
}
