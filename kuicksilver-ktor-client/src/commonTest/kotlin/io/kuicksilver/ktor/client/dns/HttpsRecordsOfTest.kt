// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client.dns

import io.kuicksilver.tls.KslDnsAnswer
import kotlin.test.Test
import kotlin.test.assertEquals

/** The system resolver's two answer forms (`ksl_dns_query`) into HTTPS records. */
class HttpsRecordsOfTest {
    private val h3 = hex("0001 00 0001 0003 026833")

    @Test fun messageGoesThroughTheMessageParser() {
        val msg = SvcbTestEncoder.response("a.example", listOf(SvcbTestEncoder.rr("a.example", 65, 300, h3)))
        assertEquals(listOf("h3"), httpsRecordsOf(KslDnsAnswer.Message(msg), "a.example")?.records?.single()?.alpn)
    }

    @Test fun recordListKeepsOwnerAndTtl() {
        val r = httpsRecordsOf(KslDnsAnswer.Records(listOf(KslDnsAnswer.Record("CDN.Example", 120, h3))), "a.example")!!.records.single()
        assertEquals("cdn.example", r.owner)
        assertEquals(120, r.ttlSeconds)
        assertEquals("cdn.example", r.serviceHost)
    }

    @Test fun negative_malformedRecordInTheListRejectsTheRrset() {
        val bad = hex("0001 00 0003 0003 0001bb")
        // rejected as a whole, and no failure either: the connection goes on without SVCB (section 2.2)
        assertEquals(
            emptyList(),
            httpsRecordsOf(
                KslDnsAnswer.Records(listOf(KslDnsAnswer.Record("a.example", 60, h3), KslDnsAnswer.Record("a.example", 60, bad))),
                "a.example",
            )?.records,
        )
    }

    @Test fun noneIsEmpty() {
        assertEquals(emptyList(), httpsRecordsOf(KslDnsAnswer.Records(emptyList()), "a.example")?.records)
    }
}
