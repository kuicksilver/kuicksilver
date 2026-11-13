// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.network.DestinationSort
import io.kuicksilver.ktor.network.SourceInfo
import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** One request's name resolution: each name and family once, names and families independent of each other. */
class RequestDnsTest {
    private fun addr(last: Int) = TcpAddress(byteArrayOf(192.toByte(), 0, 2, last.toByte()), 0)

    private fun v6(last: Int) =
        TcpAddress(
            ByteArray(16).also {
                it[0] = 0x20
                it[1] = 0x01
                it[2] = 0x0d
                it[3] = 0xb8.toByte()
                it[15] = last.toByte()
            },
            0,
        )

    /** A dual-stack host: each destination is its own source (RFC 6724 then orders by precedence, IPv6 first). */
    private val dual: () -> DestinationSort = { DestinationSort(sourceFor = { it }, sourceInfo = { SourceInfo(it) }) }

    /** An IPv4-only host: an IPv6 destination has no source (RFC 6724 Rule 1). */
    private val v4Only: () -> DestinationSort =
        { DestinationSort(sourceFor = { if (it.isIpv6) null else it }, sourceInfo = { SourceInfo(it) }) }

    private fun dns(
        sort: () -> DestinationSort = dual,
        resolve: suspend (String, Boolean) -> List<TcpAddress>,
    ) = RequestDns(Nat64.offForTest(), sort, resolve)

    private suspend fun RequestDns.texts(host: String) = lookup(host, 443).map { it.toString() }

    @Test fun namesResolveInParallel() =
        runTest {
            // a name that hangs does not hold up another (RFC 9460 section 5 relies on parallel queries)
            val slow = CompletableDeferred<Unit>()
            val dns =
                dns { name, v6 ->
                    if (v6) return@dns emptyList()
                    if (name == "slow.example") slow.await()
                    listOf(addr(if (name == "slow.example") 1 else 2))
                }
            val a = async { dns.lookup("slow.example", 443) }
            testScheduler.runCurrent()
            assertEquals(listOf("192.0.2.2:443"), dns.texts("fast.example")) // while slow.example is pending
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

    @Test fun familiesAreSeparateQueries() =
        runTest {
            // RFC 8305 section 3: AAAA and A asked separately; one that hangs does not hold up the other's answer
            val asked = mutableListOf<Boolean>()
            val aaaa = CompletableDeferred<Unit>()
            val dns =
                dns { _, v6 ->
                    asked += v6
                    if (v6) {
                        aaaa.await()
                        listOf(v6(1))
                    } else {
                        listOf(addr(1))
                    }
                }
            val r = dns.resolution("a.example", 443)
            assertEquals(listOf("192.0.2.1:443"), r.addresses(false).map { it.toString() })
            val six = async { r.addresses(true) }
            testScheduler.runCurrent()
            assertEquals(listOf(false, true), asked)
            aaaa.complete(Unit)
            assertEquals(listOf("[2001:db8::1]:443"), six.await().map { it.toString() })
        }

    @Test fun oneLookupPerNameAndFamilyAndCancelledCallerLeavesNoAnswer() =
        runTest {
            var calls = 0
            val gate = CompletableDeferred<Unit>()
            val dns =
                dns { _, v6 ->
                    if (v6) return@dns emptyList()
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
                dns { _, v6 ->
                    if (v6) return@dns emptyList()
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

    @Test fun lookupSortsByRfc6724() =
        runTest {
            // RFC 8305 section 4: "the client MUST sort the addresses received up to this point using Destination Address
            // Selection": on a dual-stack host IPv6 first, on an IPv4-only one IPv4 first, whatever order the answers came in
            val answer: suspend (String, Boolean) -> List<TcpAddress> = { _, v6 -> if (v6) listOf(v6(1)) else listOf(addr(9)) }
            assertEquals(listOf("[2001:db8::1]:443", "192.0.2.9:443"), dns(dual, answer).texts("a.example"))
            assertEquals(listOf("192.0.2.9:443", "[2001:db8::1]:443"), dns(v4Only, answer).texts("a.example"))
        }

    @Test fun literalsAreNeverLookedUp() =
        runTest {
            val dns = dns { name, _ -> error("looked up: $name") }
            assertEquals(listOf("192.0.2.7:443"), dns.texts("192.0.2.7"))
            assertEquals(listOf("[2001:db8::7]:443"), dns.texts("[2001:db8::7]"))
            val r = dns.resolution("[2001:db8::7]", 8443)
            assertEquals(listOf("[2001:db8::7]:8443"), r.addresses(true).map { it.toString() })
            assertEquals(emptyList(), r.addresses(false))
        }

    // ---- addresses an HTTPS answer carried (RFC 9460 section 5): one family alone is used, the other still looked up

    @Test fun seededIpv4IsUsedAndIpv6StillLookedUp() =
        runTest {
            // section 5: the A records of the answer are the A answer, no query for them; the AAAA query still runs
            val asked = mutableListOf<Boolean>()
            val dns =
                dns { _, v6 ->
                    asked += v6
                    if (v6) listOf(v6(1)) else listOf(addr(9))
                }
            dns.seed("a.example", listOf(addr(1).bytes))
            assertEquals(listOf("[2001:db8::1]:443", "192.0.2.1:443"), dns.texts("a.example"))
            assertEquals(listOf(true), asked)
        }

    @Test fun negative_seededIpv6OnAnIpv4OnlyHostPutsIpv4First() =
        runTest {
            // an IPv4-only host: the AAAA of the answer has no source (RFC 6724 Rule 1) and goes last
            val dns = dns(v4Only) { _, v6 -> if (v6) emptyList() else listOf(addr(9)) }
            dns.seed("a.example", listOf(v6(7).bytes))
            assertEquals(listOf("192.0.2.9:443", "[2001:db8::7]:443"), dns.texts("a.example"))
        }

    @Test fun negative_seededIpv4DoesNotWaitForAStalledIpv6LookupInARace() =
        runTest {
            // the race takes the seeded A at once and the stalled AAAA lookup never holds it past the resolution delay
            val never = CompletableDeferred<Unit>()
            val dns =
                dns { _, v6 ->
                    if (v6) never.await()
                    error("A was seeded")
                }
            dns.seed("a.example", listOf(addr(1).bytes))
            val r = dns.resolution("a.example", 443)
            val won =
                io.kuicksilver.ktor.network.raceAddresses(
                    "a.example",
                    r,
                    kotlin.time.Duration.parse("250ms"),
                    dns.order(),
                    connect = { it },
                    close = {},
                )
            assertEquals("192.0.2.1:443", won.toString())
            assertEquals(50L, testScheduler.currentTime) // the Resolution Delay of RFC 8305 section 3
        }

    @Test fun seededIpv6AloneIsUsedOnADns64Network() =
        runTest {
            // DNS64 (RFC 9460 section 4.2.1: the resolver "MAY omit the A records"): the AAAA records the answer carried
            // are used; the lookup of the other family fails, which changes nothing
            var asked = 0
            val dns =
                dns { _, _ ->
                    asked++
                    throw kotlinx.io.IOException("no A records")
                }
            dns.seed("a.example", listOf(v6(7).bytes))
            assertEquals(listOf("[2001:db8::7]:443"), dns.texts("a.example"))
            assertEquals(1, asked)
        }

    @Test fun seededBothFamiliesNeedNoLookupAndAreSorted() =
        runTest {
            val dns = dns(v4Only) { _, _ -> error("not looked up") }
            dns.seed("a.example", listOf(v6(1).bytes, addr(1).bytes, v6(2).bytes, addr(2).bytes))
            assertEquals(listOf("192.0.2.1:443", "192.0.2.2:443", "[2001:db8::1]:443", "[2001:db8::2]:443"), dns.texts("a.example"))
            val other = dns(dual) { _, _ -> error("not looked up") }
            other.seed("a.example", listOf(addr(1).bytes, v6(1).bytes))
            assertEquals(listOf("[2001:db8::1]:443", "192.0.2.1:443"), other.texts("a.example"))
        }

    // ---- NAT64 (RFC 8305 section 7)

    private val wkpAnswer = AddressRecords(listOf(TcpAddressText.v6("64:ff9b::c000:aa") to 600L))

    /** An IPv6-only host with a NAT64 whose only IPv4 route is to 10.0.0.0/8 (a VPN). */
    private fun kotlinx.coroutines.test.TestScope.nat64() =
        Nat64(
            ExpiryClock { 0L },
            sourceFor = { d ->
                if (d.isIpv6) {
                    v6(9)
                } else if (d.bytes[0].toInt() == 10) {
                    TcpAddress(byteArrayOf(10, 0, 0, 2), 0)
                } else {
                    null
                }
            },
            query = { wkpAnswer },
            platformSynthesize = { null },
            platformPrefixes = { null },
            scope = backgroundScope,
        )

    private val global = TcpAddress(byteArrayOf(93, 184.toByte(), 216.toByte(), 34), 0)

    @Test fun nat64SynthesizesIpv4LiteralsAndAnswers() =
        runTest {
            val dns = RequestDns(nat64(), dual) { _, v6 -> if (v6) emptyList() else listOf(global) }
            // section 7.1: an IPv4 literal becomes the IPv6 answer
            val lit = dns.resolution("93.184.216.34", 443)
            assertTrue(lit.ipv6Only)
            assertEquals(listOf("[64:ff9b::5db8:d822]:443"), lit.addresses(true).map { it.toString() })
            assertEquals(emptyList(), lit.addresses(false))
            // an A answer of a name comes back synthesized
            val name = dns.resolution("a.example", 443)
            assertEquals(listOf("[64:ff9b::5db8:d822]:443"), name.addresses(false).map { it.toString() })
        }

    /** The HTTP/3 pool compares a connection's address with these: the A answer and, on an IPv6-only network, its synthesis. */
    @Test fun answeredDestinationsAddTheNat64Synthesis() =
        runTest {
            val dns = RequestDns(nat64(), dual) { _, v6 -> if (v6) emptyList() else listOf(global) }
            assertEquals(
                listOf("93.184.216.34:443", "[64:ff9b::5db8:d822]:443"),
                dns.answeredDestinations("a.example", 443).map { it.toString() },
            )
        }

    @Test fun negative_loopbackLiteralOnAnIpv6OnlyNetworkStaysIpv4() =
        runTest {
            val dns = RequestDns(nat64(), dual) { _, _ -> error("not looked up") }
            val lit = dns.resolution("127.0.0.1", 8080)
            assertEquals(emptyList(), lit.addresses(true))
            assertEquals(listOf("127.0.0.1:8080"), lit.addresses(false).map { it.toString() })
        }

    @Test fun negative_aRoutedPrivateIpv4AnswerStaysIpv4() =
        runTest {
            val dns = RequestDns(nat64(), dual) { _, v6 -> if (v6) emptyList() else listOf(TcpAddress(byteArrayOf(10, 1, 2, 3), 0)) }
            assertEquals(listOf("10.1.2.3:443"), dns.resolution("intranet.example", 443).addresses(false).map { it.toString() })
        }

    @Test fun negative_aNameWithAaaaNeverWaitsForTheNat64Prefix() =
        runTest {
            // H2: the discovery runs only when an address needs synthesis
            var asked = 0
            val n =
                Nat64(
                    ExpiryClock { 0L },
                    sourceFor = { d -> if (d.isIpv6) v6(9) else null },
                    query = {
                        asked++
                        kotlinx.coroutines.awaitCancellation()
                    },
                    platformSynthesize = { null },
                    platformPrefixes = { null },
                    scope = backgroundScope,
                )
            val dns = RequestDns(n, dual) { _, v6 -> if (v6) listOf(v6(1)) else error("not asked") }
            assertEquals(listOf("[2001:db8::1]:443"), dns.resolution("a.example", 443).addresses(true).map { it.toString() })
            assertEquals(0, asked)
        }

    @Test fun negative_noSynthesisOnADualStackNetwork() =
        runTest {
            val n =
                Nat64(
                    ExpiryClock { 0L },
                    sourceFor = { d -> if (d.isIpv6) v6(9) else addr(100) },
                    query = { error("not asked") },
                    platformSynthesize = { error("not asked") },
                    platformPrefixes = { error("not asked") },
                )
            val dns = RequestDns(n, dual) { _, _ -> error("not looked up") }
            val lit = dns.resolution("93.184.216.34", 443)
            assertEquals(false, lit.ipv6Only)
            assertEquals(listOf("93.184.216.34:443"), lit.addresses(false).map { it.toString() })
        }
}
