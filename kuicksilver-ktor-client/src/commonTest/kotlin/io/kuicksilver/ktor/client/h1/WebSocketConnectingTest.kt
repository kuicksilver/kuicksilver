// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.kuicksilver.ktor.network.TcpAddress
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

    /**
     * One remote host, one key (review 2026-10-28 N3): an IPv4-mapped IPv6 address (Kotlin/Native's getaddrinfo keeps the
     * AF_INET6 form, and a resolver may return mapped AAAA records) is its IPv4 address, and a host name a proxy resolves
     * is compared without case and without its final dot.
     */
    @Test fun keysOfOneRemoteHostAreEqual() {
        val v4 = TcpAddress(byteArrayOf(127, 0, 0, 1), 80)
        val mapped = TcpAddress(ByteArray(10) + byteArrayOf(-1, -1, 127, 0, 0, 1), 443)
        assertEquals(WebSocketConnecting.addressKey(v4), WebSocketConnecting.addressKey(mapped))
        assertEquals("address 127.0.0.1", WebSocketConnecting.addressKey(mapped))
        assertEquals(WebSocketConnecting.nameKey("example.com"), WebSocketConnecting.nameKey("Example.COM."))
        assertEquals("name ::1", WebSocketConnecting.nameKey("[::1]"))
    }

    /** Addresses that only look alike stay apart: ::1, an IPv4-compatible-like ::7f00:1, and 64:ff9b::7f00:1 (NAT64). */
    @Test fun keysOfOtherHostsDiffer() {
        val v4 = WebSocketConnecting.addressKey(TcpAddress(byteArrayOf(127, 0, 0, 1), 80))
        val compatible = WebSocketConnecting.addressKey(TcpAddress(ByteArray(12) + byteArrayOf(127, 0, 0, 1), 80))
        val nat64 =
            WebSocketConnecting.addressKey(
                TcpAddress(byteArrayOf(0, 0x64, -1, -101) + ByteArray(8) + byteArrayOf(127, 0, 0, 1), 80),
            )
        assertTrue(v4 != compatible && v4 != nat64 && compatible != nat64, "$v4 / $compatible / $nat64")
        assertTrue(WebSocketConnecting.nameKey("example.com") != WebSocketConnecting.nameKey("example.org"))
    }

    /** tryAcquire takes free keys at once, and gives nothing (and holds nothing) when any of them is held. */
    @Test fun tryAcquireTakesFreeKeysOnly() =
        runTest {
            val c = WebSocketConnecting()
            val first = c.tryAcquire(listOf("address 127.0.0.1"))!!
            assertEquals(null, c.tryAcquire(listOf("address 127.0.0.2", "address 127.0.0.1")))
            assertEquals(1, c.size(), "a refused tryAcquire left an entry")
            val other = c.tryAcquire(listOf("address 127.0.0.2"))!!
            first.release()
            other.release()
            assertEquals(0, c.size())
        }
}
