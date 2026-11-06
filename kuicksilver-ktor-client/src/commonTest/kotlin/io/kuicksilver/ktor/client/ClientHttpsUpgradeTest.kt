// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.Url
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.client.dns.SvcbRecord
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9460 section 9.5: before an `http` request the client looks up the HTTPS records of the matching `https` URL, and
 * when there is an AliasMode or a compatible ServiceMode record it behaves as if it had received a 307 to that URL, trusting
 * it no more than a cleartext 307.
 */
class ClientHttpsUpgradeTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun rec(
        owner: String,
        priority: Int,
        target: String,
        vararg alpn: String,
        noDefaultAlpn: Boolean = false,
    ) = SvcbRecord(priority, target, alpn.toList(), noDefaultAlpn, null, emptyList(), emptyList(), 300, owner)

    private val asked = ArrayList<String>()
    private val lock = Mutex()

    private fun client(
        answers: Map<String, List<SvcbRecord>>,
        follow: Boolean = true,
        source: HttpsRecordSource? = null,
        more: KuicksilverEngineConfig.() -> Unit = {},
    ) = testClient(Http3DiscoveryMode.Auto, engine = {
        resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
        connectTimeout = 30.seconds
        http3 {
            httpsRecords = source ?: HttpsRecordsForTest { n ->
                lock.withLock { asked += n }
                answers[n] ?: emptyList()
            }
        }
        more()
    }, block = { followRedirects = follow })

    @Test fun httpWithRecordsGoesToHttps() =
        clientTest {
            val (tls, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("secure") } } }
            try {
                val name = "_$port._https.server.test"
                client(mapOf(name to listOf(rec(name, 1, ".", "h2")))).use { c ->
                    val r = c.get("http://server.test:$port/")
                    assertEquals("secure", r.bodyAsText())
                    assertEquals("https", r.call.request.url.protocol.name)
                }
            } finally {
                tls.stopSuspend(0, 0)
            }
        }

    @Test fun withoutFollowingRedirectsTheCallerSeesThe307() =
        clientTest {
            // port 80 becomes 443 (section 9.5, step 2); nothing is connected to
            client(mapOf("server.test" to listOf(rec("server.test", 0, "cdn.example"))), follow = false).use { c ->
                for (u in listOf("http://server.test/a?b=1", "http://server.test:80/a?b=1")) {
                    val r = c.get(u)
                    assertEquals(307, r.status.value)
                    assertEquals("https://server.test/a?b=1", r.headers[HttpHeaders.Location])
                }
            }
            assertEquals(listOf("server.test"), asked.distinct())
        }

    @Test fun networkChangeIsSeenBeforeTheUpgradeDecision() =
        clientTest {
            // RFC 9460 section 12: the first http request on a new network must not use the old network's records
            var network = "wifi"
            client(mapOf("server.test" to listOf(rec("server.test", 0, "cdn.example"))), follow = false, more = {
                http3 { networkId = { network } }
            }).use { c ->
                assertEquals(307, c.get("http://server.test/").status.value)
                assertEquals(307, c.get("http://server.test/").status.value)
                assertEquals(1, asked.size, "cached on the first network: $asked")
                network = "cellular"
                assertEquals(307, c.get("http://server.test/").status.value)
                assertEquals(2, asked.size, "asked again on the new network: $asked")
            }
        }

    @Test fun negative_hangingSourceDoesNotStallHttp() =
        clientTest {
            // the lookup before an http request waits as long as one before an https request: the extra wait
            val (plain, port) = testServer(plain = true) { routing { get("/") { call.respondText("plain") } } }
            try {
                client(emptyMap(), source = HttpsRecordsForTest { kotlinx.coroutines.awaitCancellation() }).use { c ->
                    val r = kotlinx.coroutines.withTimeout(5.seconds) { c.get("http://server.test:$port/") }
                    assertEquals("plain", r.bodyAsText())
                }
            } finally {
                plain.stopSuspend(0, 0)
            }
        }

    @Test fun noRecordsKeepsHttp() =
        clientTest {
            val (plain, port) = testServer(plain = true) { routing { get("/") { call.respondText("plain") } } }
            try {
                client(emptyMap()).use { c -> assertEquals("plain", c.get("http://server.test:$port/").bodyAsText()) }
                assertEquals(listOf("_$port._https.server.test"), asked)
            } finally {
                plain.stopSuspend(0, 0)
            }
        }

    @Test fun incompatibleServiceModeDoesNotRedirect() =
        clientTest {
            // "Receipt of an incompatible ServiceMode RR does not trigger the redirect behavior."
            val (plain, port) = testServer(plain = true) { routing { get("/") { call.respondText("plain") } } }
            try {
                val name = "_$port._https.server.test"
                client(mapOf(name to listOf(rec(name, 1, ".", "foo", noDefaultAlpn = true)))).use { c ->
                    assertEquals("plain", c.get("http://server.test:$port/").bodyAsText())
                }
            } finally {
                plain.stopSuspend(0, 0)
            }
        }

    @Test fun aliasToDotDoesNotRedirect() =
        clientTest {
            // section 12: an AliasMode "." is ignored
            val (plain, port) = testServer(plain = true) { routing { get("/") { call.respondText("plain") } } }
            try {
                val name = "_$port._https.server.test"
                client(mapOf(name to listOf(rec(name, 0, ".")))).use { c ->
                    assertEquals("plain", c.get("http://server.test:$port/").bodyAsText())
                }
            } finally {
                plain.stopSuspend(0, 0)
            }
        }

    @Test fun proxiedRequestsAreNotLookedUp() =
        clientTest {
            // section 3.2: with a proxy the engine does no SVCB resolution at all
            val (plain, port) = testServer(plain = true) { routing { get("/") { call.respondText("plain") } } }
            try {
                // the "proxy" is the plain server itself: it answers the absolute-form request as an origin would
                client(mapOf("server.test" to listOf(rec("server.test", 0, "cdn.example"))), more = {
                    proxy = ProxyBuilder.http(Url("http://127.0.0.1:$port"))
                }).use { c -> c.get("http://server.test/") }
                assertEquals(emptyList(), asked)
            } finally {
                plain.stopSuspend(0, 0)
            }
        }

    @Test fun negative_failedSecureLookupAbandonsTheHttpRequest() =
        clientTest {
            // section 3.1, and section 12: dropping the answers must not prevent the https upgrade
            val source =
                HttpsRecordSource.Exchange(secure = true) { q ->
                    io.kuicksilver.ktor.client.dns.SvcbTestEncoder
                        .response("server.test", emptyList(), rcode = 2)
                        .also {
                            it[0] = q[0]
                            it[1] = q[1]
                        }
                }
            client(emptyMap(), source = source).use { c ->
                val e = assertFailsWith<Exception> { c.get("http://server.test/") }
                assertTrue("RFC 9460" in e.message.orEmpty(), "${e.message}")
            }
        }
}
