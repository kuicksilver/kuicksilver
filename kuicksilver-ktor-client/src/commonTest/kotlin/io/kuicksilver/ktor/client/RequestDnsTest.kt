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

    /** A family order whose probe finds an IPv6 and an IPv4 source, or only what [v6Source] and [v4Source] say. */
    private fun order(
        v6Source: Boolean = true,
        v4Source: Boolean = true,
    ) = AddressFamilyOrder(ExpiryClock { 0L }) { d ->
        when {
            d.isIpv6 && v6Source -> {
                TcpAddress(
                    ByteArray(16).also {
                        it[0] = 0x20
                        it[1] = 0x01
                        it[2] = 0x0d
                        it[3] = 0xb8.toByte()
                        it[15] =
                            100
                    },
                    0,
                )
            }

            // 2001:db8::100
            !d.isIpv6 && v4Source -> {
                addr(100)
            }

            else -> {
                null
            }
        }
    }

    private suspend fun RequestDns.texts(host: String) = lookup(host, 443).map { it.toString() }

    @Test fun seededIpv4IsUsedAndIpv6StillLookedUp() =
        runTest {
            // section 5: the A records of the answer are used without waiting for a query; the lookup still runs, and its
            // AAAA records join when it answers within the resolution delay, in the order the platform resolver sorted
            // (RFC 8305 section 4: "the client MUST sort the addresses received up to this point using Destination Address
            // Selection"): IPv6 first here
            var asked = 0
            val dns =
                RequestDns(order()) { _, _ ->
                    asked++
                    listOf(v6(1), addr(9))
                }
            dns.seed("a.example", listOf(addr(1).bytes))
            assertEquals(listOf("[2001::1]:443", "192.0.2.1:443"), dns.texts("a.example"))
            assertEquals(1, asked)
        }

    @Test fun seededIpv4KeepsTheResolversIpv4FirstOrder() =
        runTest {
            // a host whose resolver sorts IPv4 first (its IPv6 is not usable for this destination): that order is kept
            val dns = RequestDns(order()) { _, _ -> listOf(addr(9), v6(1)) }
            dns.seed("a.example", listOf(addr(1).bytes))
            assertEquals(listOf("192.0.2.1:443", "[2001::1]:443"), dns.texts("a.example"))
        }

    @Test fun negative_seededIpv6OnAnIpv4OnlyHostPutsIpv4First() =
        runTest {
            // an IPv4-only host: getaddrinfo answers A only, so its addresses lead and the AAAA of the answer comes last
            // (QUIC takes the first address; an IPv6 one would fail there)
            val dns = RequestDns(order(v6Source = false)) { _, _ -> listOf(addr(9)) }
            dns.seed("a.example", listOf(v6(7).bytes))
            assertEquals(listOf("192.0.2.9:443", "[2001::7]:443"), dns.texts("a.example"))
        }

    @Test fun negative_seededIpv4DoesNotWaitForAStalledIpv6Lookup() =
        runTest {
            // an IPv4-only target (A only in the Additional section): the lookup of the other family stalls, and the
            // seeded A is used after the resolution delay, not after the lookup
            val never = CompletableDeferred<Unit>()
            var asked = 0
            val dns =
                RequestDns(order()) { _, _ ->
                    asked++
                    never.await()
                    listOf(v6(1))
                }
            dns.seed("a.example", listOf(addr(1).bytes))
            assertEquals(listOf("192.0.2.1:443"), dns.texts("a.example"))
            assertEquals(1, asked) // the AAAA lookup was made
            assertTrue(testScheduler.currentTime <= RequestDns.RESOLUTION_DELAY.inWholeMilliseconds, "${testScheduler.currentTime} ms")
        }

    @Test fun seededIpv6AloneIsUsedOnADns64Network() =
        runTest {
            // DNS64 (RFC 9460 section 4.2.1: the resolver "MAY omit the A records"): the AAAA records the answer carried
            // are used; the lookup of the other family finds none, and a failure of it changes nothing
            var asked = 0
            val dns =
                RequestDns(order(v4Source = false)) { _, _ ->
                    asked++
                    throw kotlinx.io.IOException("no A records")
                }
            dns.seed("a.example", listOf(v6(7).bytes))
            assertEquals(listOf("[2001::7]:443"), dns.texts("a.example"))
            assertEquals(1, asked)
        }

    @Test fun seededBothFamiliesNeedNoLookup() =
        runTest {
            var asked = 0
            val dns =
                RequestDns(order()) { _, _ ->
                    asked++
                    listOf(addr(9))
                }
            dns.seed("a.example", listOf(addr(1).bytes, v6(1).bytes))
            assertEquals(2, dns.lookup("a.example", 443).size)
            assertEquals(0, asked)
        }

    @Test fun seededBothFamiliesFollowTheSystemsFamilyOrder() =
        runTest {
            // no lookup to take the order from: the family order of the system decides, observed from the last platform
            // lookup or probed (an IPv4-only host: IPv4 first), each family in the answer's order
            val v4Only = order(v6Source = false)
            val dns = RequestDns(v4Only) { _, _ -> error("not looked up") }
            dns.seed("a.example", listOf(v6(1).bytes, addr(1).bytes, v6(2).bytes, addr(2).bytes))
            assertEquals(listOf("192.0.2.1:443", "192.0.2.2:443", "[2001::1]:443", "[2001::2]:443"), dns.texts("a.example"))
            val dual = order()
            val other = RequestDns(dual) { _, _ -> error("not looked up") }
            other.seed("a.example", listOf(addr(1).bytes, v6(1).bytes))
            assertEquals(listOf("[2001::1]:443", "192.0.2.1:443"), other.texts("a.example"))
        }
}
