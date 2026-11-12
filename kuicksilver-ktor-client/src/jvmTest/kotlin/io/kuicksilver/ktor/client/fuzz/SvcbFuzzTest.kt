// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.ktor.client.dns.DnsException
import io.kuicksilver.ktor.client.dns.DnsMessage
import io.kuicksilver.ktor.client.dns.DnsReader
import io.kuicksilver.ktor.client.dns.MAX_ENDPOINTS
import io.kuicksilver.ktor.client.dns.SvcbCodec
import io.kuicksilver.ktor.client.dns.SvcbRecord
import io.kuicksilver.ktor.client.dns.SvcbTestEncoder
import io.kuicksilver.ktor.client.dns.aliasTarget
import io.kuicksilver.ktor.client.dns.isHostName
import io.kuicksilver.ktor.client.dns.serviceEndpoints
import kotlin.random.Random
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Fuzz target `svcbMessage`: input = [mode byte][bytes]. Mode bit 0 clear: the bytes are a DNS response, read for the
 * HTTPS records of the name its question asks for and the other RRsets and addresses it carries ([DnsMessage.read]),
 * with work linear in the message (counted by its checkpoints), at most [DnsMessage.MAX_RELATED] other RRsets, and
 * addresses only for owners with both families; set: they are one HTTPS RDATA ([SvcbCodec.parseRdata]). Nothing but a
 * [DnsException] may escape, and every record read is written back ([SvcbTestEncoder]) and read again into an equal
 * one; the endpoints chosen from them are host names, at most [MAX_ENDPOINTS].
 */
class SvcbFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun svcbMessage(data: ByteArray) {
        if (data.isEmpty()) return
        val body = data.copyOfRange(1, data.size)
        val records: List<SvcbRecord> =
            try {
                if (data[0].toInt() and 1 == 0) {
                    val qname = questionName(body) ?: return
                    var checkpoints = 0
                    val a = DnsMessage.read(body, qname) { checkpoints++ }
                    // bounded, linear work: a checkpoint every 64 units, at most 18 units per record of the message
                    assertTrue(checkpoints <= body.size / 32 + 1, "$checkpoints checkpoints for ${body.size} bytes")
                    assertTrue(a.related.size <= DnsMessage.MAX_RELATED)
                    for ((owner, ad) in a.addresses) {
                        assertTrue(ad.first.any { it.size == 4 } && ad.first.any { it.size == 16 }, "both families of $owner")
                    }
                    a.records
                } else {
                    listOfNotNull(SvcbCodec.parseRdata(body, 0, body.size, "example.com", 300))
                }
            } catch (_: DnsException) {
                return
            }
        for (r in records) {
            val back = SvcbTestEncoder.encode(r)
            assertEquals(r, SvcbCodec.parseRdata(back, 0, back.size, r.owner, r.ttlSeconds), "round trip of $r")
            assertTrue(r.ttlSeconds in 0..Int.MAX_VALUE.toLong())
        }
        val endpoints = serviceEndpoints(records, 443, setOf("h3", "h2", "http/1.1"), Random(0))
        assertTrue(endpoints.size <= MAX_ENDPOINTS)
        for (e in endpoints) assertTrue(isHostName(e.host) && (e.quic || e.tcp))
        aliasTarget(records, Random(0))?.let { assertTrue(it.isNotEmpty()) }
    }

    /** The name the message's question asks for, or null when there is no readable one (the fuzzer then tries again). */
    private fun questionName(msg: ByteArray): String? =
        try {
            DnsReader(msg, 12, msg.size).name(compression = true)
        } catch (_: DnsException) {
            null
        }
}
