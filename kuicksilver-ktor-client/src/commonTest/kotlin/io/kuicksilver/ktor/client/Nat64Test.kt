// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.network.TcpAddress
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** NAT64 for RFC 8305 section 7: RFC 6052 synthesis, RFC 7050 prefix discovery and caching, the IPv6-only heuristic. */
class Nat64Test {
    private fun ip6(text: String): ByteArray = TcpAddressText.v6(text)

    private fun text(b: ByteArray) = TcpAddress(b, 0).hostText

    private val v4 = byteArrayOf(192.toByte(), 0, 2, 33)

    @Test fun rfc6052Table1AndTable2() {
        // RFC 6052 section 2.4, Tables 1 and 2: 192.0.2.33 under each prefix length
        val cases =
            listOf(
                Triple("2001:db8::", 32, "2001:db8:c000:221::"),
                Triple("2001:db8:100::", 40, "2001:db8:1c0:2:21::"),
                Triple("2001:db8:122::", 48, "2001:db8:122:c000:2:2100::"),
                Triple("2001:db8:122:300::", 56, "2001:db8:122:3c0:0:221::"),
                Triple("2001:db8:122:344::", 64, "2001:db8:122:344:c0:2:2100:0"),
                Triple("2001:db8:122:344::", 96, "2001:db8:122:344::c000:221"),
                Triple("64:ff9b::", 96, "64:ff9b::c000:221"),
            )
        for ((prefix, length, expected) in cases) {
            val p = Pref64(ip6(prefix), length)
            val a = p.synthesize(v4)
            assertEquals(expected, text(a), "/$length")
            assertEquals(v4.toList(), p.extract(a)?.toList(), "extract /$length")
        }
    }

    @Test fun negative_extractionNeedsAZeroUOctet() {
        val a = Pref64(ip6("2001:db8::"), 32).synthesize(v4).also { it[8] = 1 }
        assertEquals(null, Pref64.extractAt(a, 32))
    }

    @Test fun discoveryFindsEveryPrefixInOrder() {
        // RFC 7050 section 3: all Pref64::/n of the answer, in the order received, once each
        val wka170 = byteArrayOf(192.toByte(), 0, 0, 170.toByte())
        val nsp = Pref64(ip6("2001:db8:122::"), 48)
        val found = Pref64.fromIpv4OnlyArpa(listOf(nsp.synthesize(wka170), Pref64.WELL_KNOWN.synthesize(wka170), nsp.synthesize(wka170)))
        assertEquals(listOf(nsp, Pref64.WELL_KNOWN), found)
    }

    @Test fun negative_aWkaTwiceRepeatsTheSearchWithTheOther() {
        // a prefix that itself holds 192.0.0.170: the address has it twice, so the search goes on with 192.0.0.171, which
        // is found once, at /64
        val p = Pref64(ip6("2001:db8:c000:aa::"), 64)
        val twice = p.synthesize(byteArrayOf(192.toByte(), 0, 0, 170.toByte()))
        assertEquals(emptyList(), Pref64.fromIpv4OnlyArpa(listOf(twice)), "170 twice and no 171: no prefix")
        val withOther = twice.copyOf().also { it[9] = 0 } // 170 once no more: drop the embedded copy, keep the prefix's
        assertEquals(listOf(Pref64(ip6("2001:db8::"), 32)), Pref64.fromIpv4OnlyArpa(listOf(withOther)))
    }

    @Test fun negative_noWellKnownAddressNoPrefix() {
        assertEquals(emptyList(), Pref64.fromIpv4OnlyArpa(listOf(ip6("2001:db8::1"))))
    }

    private fun aaaaAnswer(ttl: Long) =
        AddressRecords(
            listOf(Pref64.WELL_KNOWN.synthesize(byteArrayOf(192.toByte(), 0, 0, 170.toByte())) to ttl),
        )

    private val globalV6 = TcpAddress(ip6("2001:db8::9"), 0)

    @Test fun ipv6OnlyHeuristic() {
        val clat = TcpAddress(byteArrayOf(192.toByte(), 0, 0, 4), 0) // 464XLAT: an IPv4 address and route of the platform's
        val linkLocal4 = TcpAddress(byteArrayOf(169.toByte(), 254.toByte(), 1, 1), 0)

        fun on(
            v6: TcpAddress?,
            v4: TcpAddress?,
        ) = Nat64(ExpiryClock { 0L }, sourceFor = { if (it.isIpv6) v6 else v4 }, query = { null }, platformSynthesize = { null })
            .ipv6OnlyNetwork()
        assertTrue(on(globalV6, null))
        assertTrue(on(globalV6, linkLocal4))
        assertEquals(false, on(globalV6, clat))
        assertEquals(false, on(null, null))
        assertEquals(false, on(TcpAddress(ip6("fe80::1"), 0), null))
    }

    /** An IPv6-only host whose IPv6 source is [source] (a test changes it to move to another network). */
    private class Host(
        var source: TcpAddress,
        val routed: Set<List<Byte>> = emptySet(),
    )

    private fun kotlinx.coroutines.test.TestScope.nat(
        clock: () -> Long,
        host: Host = Host(globalV6),
        query: suspend () -> AddressRecords?,
    ) = Nat64(
        ExpiryClock(clock),
        sourceFor = { d ->
            if (d.isIpv6) {
                host.source
            } else if (d.bytes.toList() in
                host.routed
            ) {
                TcpAddress(byteArrayOf(10, 0, 0, 2), 0)
            } else {
                null
            }
        },
        query = query,
        platformSynthesize = { null },
        platformPrefixes = { null },
        scope = backgroundScope,
    )

    @Test fun discoveryIsCachedForItsTtlAndRefreshedInTheBackgroundTenSecondsBefore() =
        runTest {
            var now = 0L
            var asked = 0
            val refresh = kotlinx.coroutines.CompletableDeferred<Unit>()
            val n =
                nat({ now }) {
                    asked++
                    if (asked == 2) refresh.await()
                    aaaaAnswer(600)
                }
            assertEquals(listOf(Pref64.WELL_KNOWN), n.prefixes())
            now = 589_999
            assertEquals(listOf(Pref64.WELL_KNOWN), n.prefixes())
            assertEquals(1, asked)
            now = 590_000 // RFC 7050 section 3: "ten seconds before the TTL ... expires": served while the refresh runs
            assertEquals(listOf(Pref64.WELL_KNOWN), n.prefixes())
            testScheduler.runCurrent()
            assertEquals(2, asked)
            assertEquals(listOf(Pref64.WELL_KNOWN), n.prefixes()) // still served, one refresh in flight
            assertEquals(2, asked)
            refresh.complete(Unit)
        }

    @Test fun negative_aShortTtlIsFloored() =
        runTest {
            var now = 0L
            var asked = 0
            val n =
                nat({ now }) {
                    asked++
                    aaaaAnswer(5)
                }
            n.prefixes()
            now = 30_000 // a 5 s TTL would ask on nearly every request
            n.prefixes()
            assertEquals(1, asked)
        }

    @Test fun negative_aNegativeAnswerIsNotAskedAgainWithinItsTtl() =
        runTest {
            // RFC 7050 section 3: "the node MUST obey the Time to Live (TTL) [RFC1035] of the response before resending"
            var now = 0L
            var asked = 0
            val n =
                nat({ now }) {
                    asked++
                    AddressRecords(emptyList(), negativeTtl = 300)
                }
            assertEquals(emptyList(), n.prefixes())
            now = 299_999
            n.prefixes()
            assertEquals(1, asked)
            now = 300_000
            n.prefixes()
            assertEquals(2, asked)
            // without the SOA (a record list): the negative answer holds NEGATIVE_TTL
            var asked2 = 0
            val m =
                nat({ now }) {
                    asked2++
                    AddressRecords(emptyList())
                }
            m.prefixes()
            now += Nat64.NEGATIVE_TTL.inWholeMilliseconds - 1
            m.prefixes()
            assertEquals(1, asked2)
        }

    @Test fun negative_aFailedDiscoveryBacksOff() =
        runTest {
            // no k x 2 s pile-up: a failure is not asked again for FAILURE_BACKOFF
            var now = 0L
            var asked = 0
            val n =
                nat({ now }) {
                    asked++
                    null
                }
            assertEquals(emptyList(), n.prefixes())
            assertEquals(emptyList(), n.prefixes())
            assertEquals(1, asked)
            now = Nat64.FAILURE_BACKOFF.inWholeMilliseconds
            n.prefixes()
            assertEquals(2, asked)
        }

    @Test fun concurrentNeedsShareOneQuery() =
        runTest {
            var asked = 0
            val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
            val n =
                nat({ 0L }) {
                    asked++
                    gate.await()
                    aaaaAnswer(600)
                }
            val waiting = (1..5).map { async { n.prefixes() } }
            testScheduler.runCurrent()
            gate.complete(Unit)
            waiting.forEach { assertEquals(listOf(Pref64.WELL_KNOWN), it.await()) }
            assertEquals(1, asked)
        }

    @Test fun negative_aNewIpv6NetworkDropsThePrefix() =
        runTest {
            // a network change the engine was not told of: the prefix was learnt on another /64
            var asked = 0
            val host = Host(globalV6)
            val n =
                nat({ 0L }, host) {
                    asked++
                    aaaaAnswer(600)
                }
            n.prefixes()
            host.source = TcpAddress(ip6("2001:db8:77::9"), 0)
            n.reset() // the 5 s route look is cached; a real change shows after it
            n.prefixes()
            assertEquals(2, asked)
            val m =
                nat({ 0L }, Host(globalV6)) {
                    asked++
                    aaaaAnswer(600)
                }
            m.prefixes()
            m.prefixes()
            assertEquals(3, asked)
        }

    @Test fun negative_implausiblePrefixesAreIgnored() {
        val wka = byteArrayOf(192.toByte(), 0, 0, 170.toByte())
        assertEquals(emptyList(), Pref64.fromIpv4OnlyArpa(listOf(Pref64(ip6("fe80::"), 96).synthesize(wka))))
        assertEquals(emptyList(), Pref64.fromIpv4OnlyArpa(listOf(Pref64(ip6("fd00::"), 64).synthesize(wka))))
        val localUse = Pref64(ip6("64:ff9b:1:2::"), 64)
        assertEquals(listOf(localUse), Pref64.fromIpv4OnlyArpa(listOf(localUse.synthesize(wka))))
    }

    private val global4 = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)

    @Test fun synthesizesOnlyWhatHasNoIpv4Route() =
        runTest {
            val routed10 = listOf<Byte>(10, 1, 2, 3)
            val n = nat({ 0L }, Host(globalV6, routed = setOf(routed10))) { aaaaAnswer(600) }
            assertEquals(listOf("[64:ff9b::5db8:d822]:443"), n.synthesize(global4, 443).map { it.toString() })
            // a VPN's or LAN's IPv4 route stays in use
            assertEquals(listOf("10.1.2.3:443"), n.synthesize(routed10.toByteArray(), 443).map { it.toString() })
        }

    @Test fun negative_loopbackAndNonGlobalAreNotSynthesizedWithTheWellKnownPrefix() =
        runTest {
            val n = nat({ 0L }) { aaaaAnswer(600) }
            assertEquals(listOf("127.0.0.1:80"), n.synthesize(byteArrayOf(127, 0, 0, 1), 80).map { it.toString() })
            assertEquals(listOf("169.254.1.1:80"), n.synthesize(byteArrayOf(169.toByte(), 254.toByte(), 1, 1), 80).map { it.toString() })
            // RFC 6052 section 3.1: "The Well-Known Prefix MUST NOT be used to represent non-global IPv4 addresses"
            assertEquals(listOf("192.168.1.9:80"), n.synthesize(byteArrayOf(192.toByte(), 168.toByte(), 1, 9), 80).map { it.toString() })
            // a Network-Specific Prefix may carry one
            val nsp = Pref64(ip6("2001:db8:122:344::"), 96)
            val m = nat({ 0L }) { AddressRecords(listOf(nsp.synthesize(byteArrayOf(192.toByte(), 0, 0, 170.toByte())) to 600L)) }
            assertEquals(
                listOf("[2001:db8:122:344::c0a8:109]:80"),
                m.synthesize(byteArrayOf(192.toByte(), 168.toByte(), 1, 9), 80).map {
                    it.toString()
                },
            )
        }

    @Test fun negative_noDiscoveryOffAnIpv6OnlyNetwork() =
        runTest {
            val n = Nat64(ExpiryClock { 0L }, sourceFor = { it }, query = { error("asked") }, platformSynthesize = { error("asked") })
            assertEquals(listOf("93.184.216.34:443"), n.synthesize(global4, 443).map { it.toString() })
        }

    @Test fun thePlatformsOwnSynthesisWins() =
        runTest {
            val own = ip6("2001:db8:64::5db8:d822")
            val n =
                Nat64(ExpiryClock { 0L }, sourceFor = { d ->
                    if (d.isIpv6) globalV6 else null
                }, query = { error("not asked") }, platformSynthesize = {
                    listOf(own)
                })
            assertEquals(listOf("[2001:db8:64::5db8:d822]:443"), n.synthesize(global4, 443).map { it.toString() })
        }

    @Test fun thePlatformsPrefixIsUsedBeforeDiscovery() =
        runTest {
            // Android: LinkProperties.getNat64Prefix, when the application gave the engine a ConnectivityManager
            val nsp = Pref64(ip6("2001:db8:64::"), 96)
            val n =
                Nat64(
                    ExpiryClock { 0L },
                    sourceFor = { d -> if (d.isIpv6) globalV6 else null },
                    query = { error("not asked") },
                    platformSynthesize = { null },
                    platformPrefixes = { listOf(nsp) },
                    scope = backgroundScope,
                )
            assertEquals(listOf("[2001:db8:64::5db8:d822]:443"), n.synthesize(global4, 443).map { it.toString() })
        }

    @Test fun negative_withoutAPlatformPrefixDiscoveryRuns() =
        runTest {
            var asked = 0
            val implausible = Pref64(ip6("fe80::"), 96)
            val n =
                Nat64(
                    ExpiryClock { 0L },
                    sourceFor = { d -> if (d.isIpv6) globalV6 else null },
                    query = {
                        asked++
                        aaaaAnswer(600)
                    },
                    platformSynthesize = { null },
                    platformPrefixes = { listOf(implausible) }, // an implausible one counts as none
                    scope = backgroundScope,
                )
            assertEquals(listOf("[64:ff9b::5db8:d822]:443"), n.synthesize(global4, 443).map { it.toString() })
            assertEquals(1, asked)
        }

    @Test fun addressRecordsAfterCnameAndNegativeTtl() {
        // ipv4only.arpa AAAA through a CNAME, and a NODATA answer with its SOA
        val msg =
            DnsBytes.response(
                "ipv4only.arpa",
                DnsMessage.TYPE_AAAA,
                answers =
                    listOf(
                        DnsBytes.rr("ipv4only.arpa", DnsMessage.TYPE_CNAME, 30, DnsBytes.name("x.example")),
                        DnsBytes.rr("x.example", DnsMessage.TYPE_AAAA, 600, ip6("64:ff9b::c000:aa")),
                    ),
            )
        val r = addressRecordsOf(msg, "ipv4only.arpa", DnsMessage.TYPE_AAAA)
        assertEquals(listOf("64:ff9b::c000:aa" to 600L), r.addresses.map { text(it.first) to it.second })
        val none =
            DnsBytes.response(
                "ipv4only.arpa",
                DnsMessage.TYPE_AAAA,
                authority = listOf(DnsBytes.rr("arpa", DnsMessage.TYPE_SOA, 900, DnsBytes.soa(minimum = 120))),
            )
        val n = addressRecordsOf(none, "ipv4only.arpa", DnsMessage.TYPE_AAAA)
        assertEquals(0, n.addresses.size)
        assertEquals(120L, n.negativeTtl)
    }
}

/** IPv6 text to bytes for tests (full or `::` form). */
internal object TcpAddressText {
    fun v6(text: String): ByteArray {
        val (head, tail) = if ("::" in text) text.split("::").let { it[0] to it[1] } else text to ""
        val h = if (head.isEmpty()) emptyList() else head.split(':')
        val t = if (tail.isEmpty()) emptyList() else tail.split(':')
        val groups = h + List(8 - h.size - t.size) { "0" } + t
        val b = ByteArray(16)
        groups.forEachIndexed { i, g ->
            val v = g.toInt(16)
            b[2 * i] = (v shr 8).toByte()
            b[2 * i + 1] = v.toByte()
        }
        return b
    }
}

/** DNS messages for tests: a response to one question with answer and authority records (no compression). */
internal object DnsBytes {
    fun name(n: String): ByteArray =
        n.trimEnd('.').split('.').filter { it.isNotEmpty() }.fold(ByteArray(0)) { acc, l ->
            acc + byteArrayOf(l.length.toByte()) +
                l.encodeToByteArray()
        } +
            byteArrayOf(0)

    private fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())

    private fun u32(v: Long) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    fun rr(
        owner: String,
        type: Int,
        ttl: Long,
        rdata: ByteArray,
    ): ByteArray = name(owner) + u16(type) + u16(1) + u32(ttl) + u16(rdata.size) + rdata

    fun soa(minimum: Long): ByteArray = name("ns.example") + name("host.example") + u32(1) + u32(2) + u32(3) + u32(4) + u32(minimum)

    fun response(
        qname: String,
        type: Int,
        answers: List<ByteArray> = emptyList(),
        authority: List<ByteArray> = emptyList(),
        rcode: Int = 0,
    ): ByteArray =
        u16(0) + u16(0x8180 or rcode) + u16(1) + u16(answers.size) + u16(authority.size) + u16(0) + name(qname) + u16(type) + u16(1) +
            answers.fold(ByteArray(0)) { a, b -> a + b } + authority.fold(ByteArray(0)) { a, b -> a + b }
}
