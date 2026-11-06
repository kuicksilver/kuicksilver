// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.client.dns.SvcbTestEncoder
import io.kuicksilver.ktor.client.dns.hex
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.awaitCancellation
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Failed and malformed HTTPS record answers (RFC 9460 sections 2.2 and 3.1): a malformed RRset always falls back to the
 * origin without SVCB; a failed resolution does too over plain DNS, but abandons the request when the answers are
 * cryptographically protected (`Exchange(secure = true)`), against a downgrade by an active attacker.
 */
class ClientHttpsFailureTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun client(
        source: HttpsRecordSource,
        connectTimeout: kotlin.time.Duration = 30.seconds,
    ) = testClient(Http3DiscoveryMode.Auto, engine = {
        resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
        this.connectTimeout = connectTimeout
        http3 { httpsRecords = source }
    })

    private suspend fun origin() =
        testServer(configure = {
            http3 = false
            altSvc = false
        }) { routing { get("/") { call.respondText("origin") } } }

    private val servfail: suspend (ByteArray) -> ByteArray = { q -> SvcbTestEncoder.response(questionName(q), emptyList(), rcode = 2) }

    private fun questionName(q: ByteArray): String {
        val labels = ArrayList<String>()
        var p = 12
        while (q[p].toInt() != 0) {
            val l = q[p].toInt()
            labels += q.copyOfRange(p + 1, p + 1 + l).decodeToString()
            p += l + 1
        }
        return labels.joinToString(".")
    }

    @Test fun failureOverPlainDnsFallsBackToTheOrigin() =
        clientTest {
            // section 3.1: "If DNS responses are not cryptographically protected, clients MAY treat SVCB resolution failure as ... nonfatal"
            val (server, port) = origin()
            try {
                client(HttpsRecordSource.Exchange(exchange = servfail)).use { c ->
                    assertEquals("origin", c.get("https://server.test:$port/").bodyAsText())
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun negative_failureOverSecureDnsAbandonsTheRequest() =
        clientTest {
            // section 3.1: SERVFAIL over a protected transport: "the client SHOULD abandon its attempt"
            val (server, port) = origin()
            try {
                client(HttpsRecordSource.Exchange(secure = true, exchange = servfail)).use { c ->
                    val e = assertFailsWith<Exception> { c.get("https://server.test:$port/") }
                    assertTrue("RFC 9460" in e.message.orEmpty(), "${e.message}")
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun negative_timeoutOverSecureDnsAbandonsTheRequest() =
        clientTest {
            // section 3.1: a timeout too; the request waits for a protected answer instead of going on after 50 ms
            val (server, port) = origin()
            try {
                client(HttpsRecordSource.Exchange(secure = true) { awaitCancellation() }, connectTimeout = 1.seconds).use { c ->
                    assertFailsWith<Exception> { c.get("https://server.test:$port/") }
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun malformedRrsetFallsBackEvenOverSecureDns() =
        clientTest {
            // section 2.2: "the client MUST reject the entire RRset and fall back to non-SVCB connection establishment"
            val (server, port) = origin()
            try {
                val bad = hex("0001 00 0003 0003 0001bb") // a three-byte port
                val source =
                    HttpsRecordSource.Exchange(secure = true) { q ->
                        val n = questionName(q)
                        SvcbTestEncoder.response(n, listOf(SvcbTestEncoder.rr(n, 65, 300, bad)))
                    }
                client(source).use { c -> assertEquals("origin", c.get("https://server.test:$port/").bodyAsText()) }
            } finally {
                server.stopSuspend(0, 0)
            }
        }
}
