// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import io.kuicksilver.ktor.client.dns.SvcbTestEncoder.response
import io.kuicksilver.ktor.client.dns.SvcbTestEncoder.rr
import kotlinx.coroutines.CancellationException
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * DNS messages around the HTTPS records: the query (RFC 1035 section 4.1, RFC 8484 section 4.1 for its ID), the answer
 * section with its CNAME chain and name compression (RFC 1035 section 4.1.4), and the choice of an h3 endpoint (RFC 9460
 * sections 2.4.1, 2.5.2 and 9.1).
 */
class DnsMessageTest {
    private val h3Here = hex("0001 00 0001 0003 026833")

    private fun service(
        priority: Int,
        target: String,
        vararg alpn: String,
        port: Int? = null,
    ): ByteArray {
        val r = SvcbRecord(priority, target, alpn.toList(), false, port, emptyList(), emptyList(), 0, "x")
        return SvcbTestEncoder.encode(r)
    }

    @Test fun queryIsRfc8484Shaped() {
        val q = DnsMessage.query("a.example", 65)
        // ID 0 (RFC 8484 section 4.1), RD, one question, a.example HTTPS IN
        assertContentEquals(hex("0000 0100 0001 0000 0000 0000 0161 076578616d706c65 00 0041 0001"), q)
    }

    @Test fun negative_queryRejectsBadNames() {
        assertFailsWith<IllegalArgumentException> { DnsMessage.query("", 65) }
        assertFailsWith<IllegalArgumentException> { DnsMessage.query("a".repeat(64) + ".example", 65) }
        assertFailsWith<IllegalArgumentException> { DnsMessage.query(List(5) { "a".repeat(60) }.joinToString("."), 65) }
        assertFailsWith<IllegalArgumentException> { DnsMessage.query("a..example", 65) }
    }

    @Test fun answersOfTheName() {
        val msg = response("a.example", listOf(rr("a.example", 65, 300, h3Here)))
        val r = DnsMessage.answers(msg, "a.example").single()
        assertEquals(listOf("h3"), r.alpn)
        assertEquals("a.example", r.owner)
        assertEquals(300, r.ttlSeconds)
    }

    @Test fun ownerMatchIsCaseInsensitive() {
        val msg = response("A.Example", listOf(rr("a.EXAMPLE", 65, 300, h3Here)))
        assertEquals(1, DnsMessage.answers(msg, "a.example").size)
    }

    @Test fun cnameChainFollowedAndMinTtl() {
        val msg =
            response(
                "a.example",
                listOf(
                    rr("a.example", 5, 30, SvcbTestEncoder.name("b.example")),
                    rr("b.example", 5, 600, SvcbTestEncoder.name("c.example")),
                    rr("c.example", 65, 300, h3Here),
                ),
            )
        val r = DnsMessage.answers(msg, "a.example").single()
        assertEquals("c.example", r.owner)
        assertEquals(30, r.ttlSeconds)
    }

    @Test fun negative_cnameLoopEndsWithoutRecords() {
        val msg =
            response(
                "a.example",
                listOf(
                    rr("a.example", 5, 30, SvcbTestEncoder.name("b.example")),
                    rr("b.example", 5, 30, SvcbTestEncoder.name("a.example")),
                ),
            )
        assertEquals(emptyList(), DnsMessage.answers(msg, "a.example"))
    }

    @Test fun answerForOtherNameIgnored() {
        val msg = response("a.example", listOf(rr("evil.example", 65, 300, h3Here), rr("a.example", 1, 300, hex("c0000201"))))
        assertEquals(emptyList(), DnsMessage.answers(msg, "a.example"))
    }

    @Test fun otherTypeAndClassIgnored() {
        val chaos = rr("a.example", 65, 300, h3Here).also { it[it.size - h3Here.size - 7] = 3 } // class CH
        val msg = response("a.example", listOf(chaos, rr("a.example", 64, 300, h3Here)))
        assertEquals(emptyList(), DnsMessage.answers(msg, "a.example"))
    }

    @Test fun nxdomainIsEmpty() {
        assertEquals(emptyList(), DnsMessage.answers(response("a.example", emptyList(), rcode = 3), "a.example"))
    }

    @Test fun negative_serverFailureIsAnError() {
        assertFailsWith<DnsException> { DnsMessage.answers(response("a.example", emptyList(), rcode = 2), "a.example") }
    }

    @Test fun negative_truncatedResponseIsAnError() {
        val tc = response("a.example", emptyList(), flags = 0x8380)
        assertFailsWith<DnsException> { DnsMessage.answers(tc, "a.example") }
    }

    @Test fun negative_queryInsteadOfResponseIsAnError() {
        assertFailsWith<DnsFormatException> { DnsMessage.answers(DnsMessage.query("a.example", 65), "a.example") }
    }

    @Test fun negative_questionForAnotherNameIsAnError() {
        assertFailsWith<DnsFormatException> { DnsMessage.answers(response("b.example", emptyList()), "a.example") }
        assertFailsWith<DnsFormatException> { DnsMessage.answers(response("a.example", emptyList(), qtype = 1), "a.example") }
    }

    @Test fun compressedOwnerNamesAreFollowed() {
        // the answer's owner is a pointer to the question name at offset 12
        val msg =
            response("a.example", emptyList()).let { it.copyOf().also { m -> m[7] = 1 } } + hex("c00c 0041 0001 0000012c 000a") + h3Here
        assertEquals(1, DnsMessage.answers(msg, "a.example").size)
    }

    @Test fun negative_compressionPointerLoopFails() {
        // the owner name of the answer points at itself
        val head = response("a.example", emptyList()).let { it.copyOf().also { m -> m[7] = 1 } }
        val self = head.size
        val msg = head + hex("c0${self.toString(16).padStart(2, '0')} 0041 0001 0000012c 000a") + h3Here
        assertFailsWith<DnsFormatException> { DnsMessage.answers(msg, "a.example") }
    }

    @Test fun negative_forwardCompressionPointerFails() {
        val head = response("a.example", emptyList()).let { it.copyOf().also { m -> m[7] = 1 } }
        val ahead = head.size + 2
        val msg = head + hex("c0${ahead.toString(16).padStart(2, '0')} 0141 00 0041 0001 0000012c 000a") + h3Here
        assertFailsWith<DnsFormatException> { DnsMessage.answers(msg, "a.example") }
    }

    @Test fun negative_malformedRecordRejectsTheRrset() { // RFC 9460 section 2.2: the whole RRSet, not just the record
        val bad = hex("0001 00 0003 0003 0001bb")
        val msg = response("a.example", listOf(rr("a.example", 65, 300, h3Here), rr("a.example", 65, 300, bad)))
        assertFailsWith<DnsFormatException> { DnsMessage.answers(msg, "a.example") }
    }

    @Test fun negative_truncatedMessagesFail() {
        val msg = response("a.example", listOf(rr("a.example", 65, 300, h3Here)))
        for (n in 0 until msg.size) {
            assertFailsWith<DnsFormatException>("cut at $n") { DnsMessage.answers(msg.copyOf(n), "a.example") }
        }
    }

    @Test fun negativeTtlComesFromTheSoa() { // RFC 2308 section 5: min(SOA TTL, MINIMUM); none without an SOA
        val soa =
            SvcbTestEncoder.name("ns.example") + SvcbTestEncoder.name("host.example") + hex("00000001 00000e10 00000384 00093a80 0000003c")
        val withSoa = response("a.example", emptyList(), rcode = 3).let { it.copyOf().also { m -> m[9] = 1 } } + rr("example", 6, 900, soa)
        assertEquals(60, DnsMessage.read(withSoa, "a.example").negativeTtl)
        assertNull(DnsMessage.read(response("a.example", emptyList(), rcode = 3), "a.example").negativeTtl)
    }

    @Test fun otherRrsetsAndAddressesOfTheAnswerAreKept() { // RFC 9460 section 5: for the cache, before follow-up queries
        val alias = SvcbTestEncoder.encode(SvcbRecord(0, "cdn.example", emptyList(), false, null, emptyList(), emptyList(), 0, "x"))
        val bad = hex("0001 00 0003 0003 0001bb")
        val msg =
            response("a.example", listOf(rr("a.example", 65, 300, alias))).let { it.copyOf().also { m -> m[11] = 4 } } +
                rr("cdn.example", 65, 200, h3Here) + rr("cdn.example", 1, 30, hex("c0000201")) +
                rr("cdn.example", 28, 60, hex("20010db8000000000000000000000001")) +
                rr("bad.example", 65, 200, bad)
        val a = DnsMessage.read(msg, "a.example")
        assertEquals("cdn.example", a.records.single().target)
        assertEquals(listOf("h3"), a.related["cdn.example"]?.single()?.alpn)
        assertTrue("bad.example" !in a.related) // its malformed RRset is dropped, the one asked for stands
        val (addrs, ttl) = a.addresses.getValue("cdn.example")
        assertEquals(listOf(4, 16), addrs.map { it.size })
        assertEquals(30, ttl)
    }

    @Test fun relatedRrsetOfACnameTargetIsFiledUnderTheTargetName() { // RFC 9460 section 3, step 3: "after following CNAMEs"
        val alias = SvcbTestEncoder.encode(SvcbRecord(0, "svc.example", emptyList(), false, null, emptyList(), emptyList(), 0, "x"))
        val msg =
            response(
                "a.example",
                listOf(rr("a.example", 65, 300, alias), rr("svc.example", 5, 30, SvcbTestEncoder.name("cdn.example"))),
            ).let { it.copyOf().also { m -> m[11] = 3 } } +
                rr("cdn.example", 65, 300, h3Here) + rr("cdn.example", 1, 200, hex("c0000201")) +
                rr("cdn.example", 28, 200, hex("20010db8000000000000000000000001"))
        val a = DnsMessage.read(msg, "a.example")
        // the target's RRset is the one at the end of its chain, no longer than the CNAME that led there
        val rs = assertNotNull(a.related["svc.example"])
        assertEquals("cdn.example", rs.single().owner)
        assertEquals(30, rs.single().ttlSeconds)
        assertEquals(30, a.addresses["svc.example"]?.second)
        assertEquals(200, a.addresses["cdn.example"]?.second)
    }

    @Test fun negative_cnameTargetLeavingTheZoneIsNotInBailiwick() { // RFC 2181 section 5.4.1
        // svc.a.example is in the query's bailiwick, but its records come from cdn.other through a CNAME: they serve this
        // resolution, and are not cached beyond it
        val alias = SvcbTestEncoder.encode(SvcbRecord(0, "svc.a.example", emptyList(), false, null, emptyList(), emptyList(), 0, "x"))
        val msg =
            response(
                "a.example",
                listOf(rr("a.example", 65, 300, alias), rr("svc.a.example", 5, 30, SvcbTestEncoder.name("cdn.other"))),
            ).let { it.copyOf().also { m -> m[11] = 1 } } + rr("cdn.other", 65, 300, h3Here)
        val a = DnsMessage.read(msg, "a.example")
        assertEquals("cdn.other", a.related["svc.a.example"]?.single()?.owner)
        assertTrue(!a.inBailiwick("svc.a.example"))
        assertTrue(a.inBailiwick("www.a.example"))
    }

    @Test fun negative_recordsOfUnrelatedNamesAreNotKept() { // RFC 2181 section 5.4.1: only what the answer leads to
        val alias = SvcbTestEncoder.encode(SvcbRecord(0, "cdn.example", emptyList(), false, null, emptyList(), emptyList(), 0, "x"))
        val msg =
            response("a.example", listOf(rr("a.example", 65, 300, alias))).let { it.copyOf().also { m -> m[11] = 4 } } +
                rr("victim.example", 65, 200, h3Here) + rr("victim.example", 1, 30, hex("c0000201")) +
                rr("cdn.example", 1, 30, hex("c0000202")) + rr("cdn.example", 28, 30, hex("20010db8000000000000000000000002"))
        val a = DnsMessage.read(msg, "a.example")
        assertTrue(a.related.isEmpty(), "kept ${a.related.keys}")
        assertEquals(setOf("cdn.example"), a.addresses.keys)
    }

    @Test fun oneAddressFamilyAloneIsKept() { // RFC 9460 section 5: placed in cache before any follow-up query
        val alias = SvcbTestEncoder.encode(SvcbRecord(0, "cdn.example", emptyList(), false, null, emptyList(), emptyList(), 0, "x"))
        val service = SvcbTestEncoder.encode(SvcbRecord(1, "v4.example", listOf("h3"), false, null, emptyList(), emptyList(), 0, "x"))
        val msg =
            response("a.example", listOf(rr("a.example", 65, 300, alias))).let { it.copyOf().also { m -> m[11] = 3 } } +
                rr("cdn.example", 65, 300, service) + rr("cdn.example", 28, 30, hex("20010db8000000000000000000000001")) +
                rr("v4.example", 1, 30, hex("c0000201"))
        val a = DnsMessage.read(msg, "a.example")
        // the family that came is kept; RequestDns.seed looks up the missing one (RequestDnsTest)
        assertEquals(listOf(16), a.addresses["cdn.example"]?.first?.map { it.size })
        assertEquals(listOf(4), a.addresses["v4.example"]?.first?.map { it.size })
    }

    @Test fun negative_noRecordsThroughACnameLastNoLongerThanTheCname() { // RFC 2308 section 5, RFC 1035 section 3.2.1
        val soa =
            SvcbTestEncoder.name("ns.example") + SvcbTestEncoder.name("host.example") + hex("00000001 00000e10 00000384 00093a80 00000e10")
        for (rcode in listOf(0, 3)) { // NODATA and NXDOMAIN at the end of the chain
            val msg =
                response("www.example", listOf(rr("www.example", 5, 60, SvcbTestEncoder.name("cdn.example")))).let {
                    it.copyOf().also { m -> m[3] = (m[3].toInt() or rcode).toByte() }.also { m -> m[9] = 1 }
                } + rr("example", 6, 900, soa)
            val a = DnsMessage.read(msg, "www.example")
            assertEquals(emptyList(), a.records)
            assertEquals(60, a.negativeTtl, "rcode $rcode: the CNAME that led there expires after 60 s")
        }
        val direct = response("cdn.example", emptyList()).let { it.copyOf().also { m -> m[9] = 1 } } + rr("example", 6, 900, soa)
        assertEquals(900, DnsMessage.read(direct, "cdn.example").negativeTtl)
    }

    // ---- bounded work on hostile answers (RFC 9460 section 9.2.2: the DNS is "an untrusted channel")

    /**
     * A response to a.example of nearly the largest DNS message size whose answer section holds [n] ServiceMode records,
     * each with an owner compressed to the question and its own three-letter TargetName (no SvcParams), and none of the
     * targets with records of its own: the worst case for following the TargetNames.
     */
    private fun manyTargets(n: Int): ByteArray {
        val abc = "abcdefghijklmnopqrstuvwxyz0123456789"
        val head =
            response("a.example", emptyList()).let {
                it.copyOf().also { m -> m[6] = (n shr 8).toByte() }.also { m ->
                    m[7] =
                        n.toByte()
                }
            }
        val out = ArrayList<Byte>(head.size + n * 19)
        out.addAll(head.toList())
        for (i in 0 until n) {
            val label = "${abc[i / 1296 % 36]}${abc[i / 36 % 36]}${abc[i % 36]}"
            out.addAll(hex("c00c 0041 0001 0000012c 0007 0001 03").toList())
            for (c in label) out += c.code.toByte()
            out += 0
        }
        return out.toByteArray()
    }

    @Test fun negative_hostileLargestAnswerIsReadInLinearTime() {
        val n = (65_535 - 27) / 19
        val msg = manyTargets(n)
        assertTrue(msg.size <= 65_535, "${msg.size} bytes")
        val start = TimeSource.Monotonic.markNow()
        val a = DnsMessage.read(msg, "a.example")
        val took = start.elapsedNow()
        assertEquals(n, a.records.size)
        assertEquals(
            n,
            a.records
                .map { it.target }
                .toSet()
                .size,
        )
        // linear work is milliseconds even on a slow, loaded machine; walking every name for every new TargetName took
        // tens of seconds at this size
        assertTrue(took < 5.seconds, "read took $took")
    }

    @Test fun negative_readStopsAtACheckpoint() { // so a lookup's timeout cancels a read in progress
        var calls = 0
        assertFailsWith<CancellationException> {
            DnsMessage.read(manyTargets(1000), "a.example") { if (++calls == 2) throw CancellationException("timed out") }
        }
        assertEquals(2, calls)
    }

    @Test fun negative_messageOverTheDnsMaximumIsRejected() { // RFC 1035 section 4.2.2, RFC 8484 section 6: 65535 bytes
        val ok = response("a.example", listOf(rr("a.example", 65, 300, h3Here)))
        assertEquals(1, DnsMessage.answers(ok + ByteArray(65_535 - ok.size), "a.example").size)
        assertFailsWith<DnsFormatException> { DnsMessage.answers(ok + ByteArray(65_536 - ok.size), "a.example") }
    }

    @Test fun negative_relatedRrsetsFollowedAreCapped() {
        fun alias(t: String) = SvcbTestEncoder.encode(SvcbRecord(0, t, emptyList(), false, null, emptyList(), emptyList(), 0, "x"))
        // a.example -> t0 -> t1 -> ... -> t40, every step's RRset in the additional section
        val extra = (0 until 40).map { rr("t$it.example", 65, 300, alias("t${it + 1}.example")) }
        val msg =
            response("a.example", listOf(rr("a.example", 65, 300, alias("t0.example")))).let {
                it.copyOf().also { m -> m[11] = extra.size.toByte() }
            } + extra.reduce { x, y -> x + y }
        val a = DnsMessage.read(msg, "a.example")
        assertEquals((0 until DnsMessage.MAX_RELATED).map { "t$it.example" }, a.related.keys.toList())
    }

    @Test fun ttlWithTopBitIsZero() { // RFC 2181 section 8
        val msg = response("a.example", listOf(rr("a.example", 65, 0x80000001L, h3Here)))
        assertEquals(0, DnsMessage.answers(msg, "a.example").single().ttlSeconds)
    }

    // ---- choosing the h3 endpoint

    private fun rec(
        priority: Int,
        target: String,
        vararg alpn: String,
        port: Int? = null,
    ) = SvcbRecord(priority, target, alpn.toList(), false, port, emptyList(), emptyList(), 300, "a.example")

    private val all = setOf("h3", "h2", "http/1.1")

    private fun first(records: List<SvcbRecord>) = serviceEndpoints(records, 443, all, Random(1)).firstOrNull()

    @Test fun serviceEndpointsPreferLowerPriorityAndSkipAliasMode() {
        val eps =
            serviceEndpoints(listOf(rec(3, "c.example", "h3"), rec(1, "b.example", "h2"), rec(2, "d.example", "h3", port = 8443)), 443, all)
        assertEquals(listOf("b.example", "d.example", "c.example"), eps.map { it.host })
        assertEquals(8443, eps[1].port)
        assertEquals(443, eps[0].port) // section 7.2: the authority's port without a port key
        // an RRSet with an AliasMode record: its ServiceMode records are ignored (RFC 9460 section 2.4.1)
        assertNull(first(listOf(rec(0, "x.example"), rec(1, "b.example", "h3"))))
        assertEquals("x.example", aliasTarget(listOf(rec(0, "x.example"), rec(1, "b.example", "h3")), Random(1)))
    }

    @Test fun negative_endpointsAreCapped() { // each endpoint is a connection attempt: a hostile RRset cannot make thousands
        val many = (0 until 100).map { rec(3 - it % 3, "t$it.example", "h3") }
        val eps = serviceEndpoints(many, 443, all, Random(1))
        assertEquals(MAX_ENDPOINTS, eps.size)
        // the lowest SvcPriority first (RFC 9460 section 3: "Clients SHOULD try higher-priority alternatives first"); the 33
        // records of priority 1 outnumber the cap
        val priority = many.associate { it.target to it.priority }
        assertEquals(setOf(1), eps.map { priority.getValue(it.host) }.toSet())
    }

    @Test fun dotTargetMeansOwner() {
        assertEquals("a.example", assertNotNull(first(listOf(rec(1, ".", "h3")))).host)
    }

    @Test fun aliasToDotIsReported() { // RFC 9460 section 2.5.1; the resolver ignores it (section 12)
        assertEquals(".", aliasTarget(listOf(rec(0, ".")), Random(1)))
    }

    @Test fun negative_targetThatIsNoHostNameIsSkipped() {
        assertNull(first(listOf(rec(1, "a\\032b.example", "h3"))))
        assertNull(first(listOf(rec(1, "a\\.b.example", "h3"))))
    }

    @Test fun httpsQueryNameIsTheHostOrThePortPrefixedName() { // RFC 9460 section 9.1
        assertEquals("a.example", httpsQueryName("a.example", 443))
        assertEquals("_8443._https.a.example", httpsQueryName("a.example", 8443))
        assertTrue(httpsQueryName("A.Example.", 443) == "a.example")
    }
}
