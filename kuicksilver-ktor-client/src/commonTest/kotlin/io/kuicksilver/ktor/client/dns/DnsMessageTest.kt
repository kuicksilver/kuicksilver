// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.dns

import io.kuicksilver.ktor.client.dns.SvcbTestEncoder.response
import io.kuicksilver.ktor.client.dns.SvcbTestEncoder.rr
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

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

    @Test fun pickH3PrefersLowerPriorityAndSkipsAliasMode() {
        val chosen = pickH3(listOf(rec(3, "c.example", "h3"), rec(1, "b.example", "h2"), rec(2, "d.example", "h3", port = 8443)))
        assertEquals("d.example", assertNotNull(chosen).serviceHost)
        assertEquals(8443, chosen.port)
        // an RRSet with an AliasMode record: its ServiceMode records are ignored (RFC 9460 section 2.4.1)
        assertNull(pickH3(listOf(rec(0, "x.example"), rec(1, "b.example", "h3"))))
        assertEquals("x.example", aliasTarget(listOf(rec(0, "x.example"), rec(1, "b.example", "h3")), Random(1)))
    }

    @Test fun dotTargetMeansOwner() {
        assertEquals("a.example", assertNotNull(pickH3(listOf(rec(1, ".", "h3")))).serviceHost)
    }

    @Test fun aliasToDotMeansNoService() { // RFC 9460 section 2.5.1
        assertEquals(".", aliasTarget(listOf(rec(0, ".")), Random(1)))
    }

    @Test fun negative_targetThatIsNoHostNameIsSkipped() {
        assertNull(pickH3(listOf(rec(1, "a\\032b.example", "h3"))))
        assertNull(pickH3(listOf(rec(1, "a\\.b.example", "h3"))))
    }

    @Test fun httpsQueryNameIsTheHostOrThePortPrefixedName() { // RFC 9460 section 9.1
        assertEquals("a.example", httpsQueryName("a.example", 443))
        assertEquals("_8443._https.a.example", httpsQueryName("a.example", 8443))
        assertTrue(httpsQueryName("A.Example.", 443) == "a.example")
    }
}
