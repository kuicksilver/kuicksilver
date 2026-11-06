// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** One request's name resolution: each name once, names independent of each other. */
class RequestDnsTest {
    private fun addr(last: Int) = TcpAddress(byteArrayOf(192.toByte(), 0, 2, last.toByte()), 0)

    @Test fun namesResolveInParallel() =
        runTest {
            // a name that hangs does not hold up another (RFC 9460 section 5 relies on parallel queries)
            val slow = CompletableDeferred<Unit>()
            val dns =
                RequestDns { name, _ ->
                    if (name == "slow.example") slow.await()
                    listOf(addr(if (name == "slow.example") 1 else 2))
                }
            val a = async { dns.lookup("slow.example", 443) }
            testScheduler.runCurrent()
            assertEquals(
                2,
                dns
                    .lookup("fast.example", 443)
                    .single()
                    .bytes[3]
                    .toInt(),
            ) // while slow.example is pending
            slow.complete(Unit)
            assertEquals(
                1,
                a
                    .await()
                    .single()
                    .bytes[3]
                    .toInt(),
            )
        }

    @Test fun oneLookupPerNameAndCancelledCallerLeavesNoAnswer() =
        runTest {
            var calls = 0
            val gate = CompletableDeferred<Unit>()
            val dns =
                RequestDns { _, _ ->
                    calls++
                    gate.await()
                    listOf(addr(1))
                }
            val first = async { dns.lookup("a.example", 443) }
            testScheduler.runCurrent()
            val second = async { dns.lookup("a.example", 443) }
            testScheduler.runCurrent()
            first.cancel() // the caller that runs the lookup goes; the waiting one looks the name up itself
            testScheduler.runCurrent()
            gate.complete(Unit)
            assertEquals(1, second.await().size)
            assertEquals(2, calls)
            assertEquals(1, dns.lookup("a.example", 80).size) // kept for the rest of the request
            assertEquals(2, calls)
        }

    @Test fun negative_cancelledLookUpUnderAContendedLockLeavesNoStuckEntry() =
        runTest {
            // the cancelled looker-up must give up its entry even when the lock is busy at that moment
            val gate = CompletableDeferred<Unit>()
            var calls = 0
            val dns =
                RequestDns { _, _ ->
                    calls++
                    if (calls == 1) gate.await()
                    listOf(addr(1))
                }
            val first = async { dns.lookup("a.example", 443) }
            testScheduler.runCurrent()
            dns.lockForTest.lock() // busy when the cancelled caller cleans up
            first.cancel()
            testScheduler.runCurrent()
            dns.lockForTest.unlock()
            val again = kotlinx.coroutines.withTimeoutOrNull(10_000) { dns.lookup("a.example", 443) }
            assertEquals(1, again?.size, "the name was left with an answer that never comes")
        }
}
