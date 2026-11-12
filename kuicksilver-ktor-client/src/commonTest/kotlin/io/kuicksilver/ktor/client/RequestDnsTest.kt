// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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

    // ---- addresses an HTTPS answer carried (RFC 9460 section 5): one family alone is used, the other still looked up

    private fun v6(last: Int) =
        TcpAddress(
            ByteArray(16).also {
                it[0] = 0x20
                it[1] = 0x01
                it[15] = last.toByte()
            },
            0,
        )

    @Test fun seededIpv4IsUsedAndIpv6StillLookedUp() =
        runTest {
            // section 5: the A records of the answer go to use without waiting for a query; the AAAA query still runs,
            // and its answer joins the race when it comes within the resolution delay
            var asked = 0
            val dns =
                RequestDns { _, _ ->
                    asked++
                    listOf(addr(9), v6(1)) // the system resolver answers both families
                }
            dns.seed("a.example", listOf(addr(1).bytes))
            val got = dns.lookup("a.example", 443)
            assertEquals(1, asked)
            // the seeded A first, then only the family the answer did not carry
            assertEquals(listOf("192.0.2.1:443", "[2001::1]:443"), got.map { it.toString() })
        }

    @Test fun negative_seededIpv4DoesNotWaitForAStalledIpv6Lookup() =
        runTest {
            // an IPv4-only target (A only in the Additional section): the lookup of the other family stalls, and the
            // seeded A is used after the resolution delay, not after the lookup
            val never = CompletableDeferred<Unit>()
            var asked = 0
            val dns =
                RequestDns { _, _ ->
                    asked++
                    never.await()
                    listOf(v6(1))
                }
            dns.seed("a.example", listOf(addr(1).bytes))
            val got = dns.lookup("a.example", 443)
            assertEquals(1, asked) // the AAAA lookup was made
            assertEquals(listOf("192.0.2.1:443"), got.map { it.toString() })
            assertTrue(testScheduler.currentTime <= RequestDns.RESOLUTION_DELAY.inWholeMilliseconds, "${testScheduler.currentTime} ms")
        }

    @Test fun seededIpv6AloneIsUsedOnADns64Network() =
        runTest {
            // DNS64 (RFC 9460 section 4.2.1: the resolver "MAY omit the A records"): the AAAA records the answer carried
            // are used; the lookup of the other family finds none, and a failure of it changes nothing
            var asked = 0
            val dns =
                RequestDns { _, _ ->
                    asked++
                    throw kotlinx.io.IOException("no A records")
                }
            dns.seed("a.example", listOf(v6(7).bytes))
            assertEquals(listOf("[2001::7]:443"), dns.lookup("a.example", 443).map { it.toString() })
            assertEquals(1, asked)
        }

    @Test fun seededBothFamiliesNeedNoLookup() =
        runTest {
            var asked = 0
            val dns =
                RequestDns { _, _ ->
                    asked++
                    listOf(addr(9))
                }
            dns.seed("a.example", listOf(addr(1).bytes, v6(1).bytes))
            assertEquals(2, dns.lookup("a.example", 443).size)
            assertEquals(0, asked)
        }
}
