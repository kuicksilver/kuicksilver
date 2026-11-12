// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.util.date.getTimeMillis
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.ktor.client.dns.SvcbRecord
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * HTTPS resource records (RFC 9460) as a source of HTTP/3 in `Auto`: a record with `alpn=h3` sends the first request to
 * HTTP/3 at once; anything else leaves the request where it was without records (an SVCB-optional client, section 3).
 */
class ClientHttpsRecordTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun record(
        owner: String,
        priority: Int,
        target: String,
        vararg alpn: String,
        port: Int? = null,
        ttl: Long = 300,
    ) = SvcbRecord(priority, target, alpn.toList(), false, port, emptyList(), emptyList(), ttl, owner)

    /** A source answering from [answers] by name and recording the names asked. */
    private class Records(
        val answers: Map<String, List<SvcbRecord>>,
    ) {
        val asked = ArrayList<String>()
        val source =
            HttpsRecordsForTest { name ->
                asked += name
                answers[name] ?: emptyList()
            }
    }

    private val loopback: suspend (String, Int) -> List<TcpAddress> = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }

    private class Events : KuicksilverEventListener() {
        val used = ArrayList<String>()
        val broken = CompletableDeferred<String>()

        override fun httpsRecordUsed(
            request: HttpRequestData,
            alternative: String,
        ) {
            used += alternative
        }

        override fun altSvcMarkedBroken(
            origin: String,
            alternative: String,
        ) {
            broken.complete(alternative)
        }
    }

    private fun client(
        source: HttpsRecordSource,
        events: KuicksilverEventListener? = null,
        more: KuicksilverEngineConfig.() -> Unit = {},
    ) = testClient(Http3DiscoveryMode.Auto, engine = {
        resolverForTest = loopback
        eventListener = events
        connectTimeout = 30.seconds
        http3 { httpsRecords = source }
        more()
    })

    /** h1 (TCP) and h3 (UDP) of the Kuicksilver server on one port, announcing no `Alt-Svc` unless [altSvc]. */
    private suspend fun h1h3(altSvc: Boolean = false): Pair<TestServer, Int> =
        testServer(configure = { this.altSvc = altSvc }) { routing { get("/") { call.respondText("ok") } } }

    @Test fun httpsRecordWithH3GoesStraightToH3() =
        h3Test {
            coroutineScope {
                val ep = h3Origin() // nothing listens on its TCP port
                try {
                    val port = ep.localAddress.port
                    val name = "_$port._https.server.test"
                    // with a port prefix "." would name _<port>._https.server.test itself (section 2.5.2): the target is explicit
                    val records = Records(mapOf(name to listOf(record(name, 1, "server.test", "h3"))))
                    val events = Events()
                    client(records.source, events).use { c ->
                        val r = c.get("https://server.test:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("h3", r.bodyAsText())
                        assertEquals(AlternativeSource.HttpsRecord, r.kuicksilverDiagnostics?.alternativeSource)
                    }
                    assertEquals(listOf(name), records.asked)
                    assertEquals(listOf("server.test:$port"), events.used)
                } finally {
                    ep.close()
                }
            }
        }

    @Test fun noH3AlpnStaysOnH1() =
        h3Test {
            val (server, port) = h1h3(altSvc = true)
            try {
                val name = "_$port._https.server.test"
                val records = Records(mapOf(name to listOf(record(name, 1, ".", "h2"))))
                val store = InMemoryAltSvcStore()
                client(records.source, more = { http3 { altSvcStore = store } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://server.test:$port/").version)
                }
                // Alt-Svc is learned from the response as without records
                assertEquals(listOf(port), store.get("https://server.test:$port").map { it.port })
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun cachedAltSvcComesFirst() =
        // the origin's records still give the TCP side and the fallback (RFC 9460 section 3); the alt-authority here is
        // the origin itself, so its records are asked for once
        h3Test {
            coroutineScope {
                val ep = h3Origin()
                try {
                    val port = ep.localAddress.port
                    val store = InMemoryAltSvcStore()
                    store.put("https://server.test:$port", listOf(AltSvcEntry("h3", null, port, getTimeMillis() + 3_600_000, false)))
                    val records = Records(emptyMap())
                    client(records.source, more = { http3 { altSvcStore = store } }).use { c ->
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                    }
                    assertEquals(listOf("_$port._https.server.test"), records.asked)
                } finally {
                    ep.close()
                }
            }
        }

    @Test fun slowAnswerMissesFirstRequestButIsCached() =
        h3Test {
            val (server, port) = h1h3()
            try {
                val name = "_$port._https.server.test"
                val gate = CompletableDeferred<Unit>()
                var queries = 0
                val source =
                    HttpsRecordsForTest { n ->
                        queries++
                        gate.await()
                        listOf(record(n, 1, "server.test", "h3"))
                    }
                // TCP starts only once QUIC failed: the pooled HTTP/1.1 connection of the first request cannot win the race
                client(source, more = {
                    http3 {
                        hardDelay = Duration.INFINITE
                        networkId = { "wifi" } // answers are cached only where a network change can be seen
                    }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val settled = CompletableDeferred<String>()
                    engine.httpsRecordsForTest!!.settledForTest = { settled.complete(it) }
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://server.test:$port/").version)
                    gate.complete(Unit)
                    assertEquals(name, withTimeout(10.seconds) { settled.await() })
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                }
                assertEquals(1, queries)
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun negative_hangingSourceDoesNotDelayBeyondExtraWait() =
        h3Test {
            val (server, port) = h1h3()
            try {
                val asked = CompletableDeferred<Unit>()
                val source =
                    HttpsRecordsForTest {
                        asked.complete(Unit)
                        awaitCancellation()
                    }
                // the source never answers and the connect timeout is far: the request goes on over TCP after the extra wait
                client(source, more = { connectTimeout = 120.seconds }).use { c ->
                    val r = withTimeout(5.seconds) { c.get("https://server.test:$port/") } // the extra wait, not the 120 s timeout
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                    assertEquals(FallbackReason.NoAlternative, r.kuicksilverDiagnostics?.fallback)
                    assertTrue(asked.isCompleted, "the source was not asked")
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun negative_hangingLookupDoesNotHoldUpClose() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val asked = CompletableDeferred<Unit>()
                val source =
                    HttpsRecordsForTest {
                        asked.complete(Unit)
                        awaitCancellation()
                    }
                // the lookup outlives its request (its answer would be cached) for up to 30 s; closing the client ends it
                val c = client(source, more = { connectTimeout = 120.seconds })
                val engine = c.engine as KuicksilverEngine
                assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://server.test:$port/").version)
                assertTrue(asked.isCompleted)
                c.close()
                withTimeout(10.seconds) { engine.cleanup.join() }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun negative_wrongCertificateAtTargetFallsBackAndMarksBroken() =
        h3Test {
            coroutineScope {
                // the record points at an HTTP/3 server whose certificate is not the origin's (expired here): HTTPS records do
                // not bypass the check against the origin's name, so the target loses and is marked broken
                val bad = h3With(TlsIdentity.fromDer(listOf(TestCerts.expired), TestCerts.expiredKey.copyOf()))
                val (server, port) =
                    testServer(configure = {
                        http3 = false
                        altSvc = false
                    }) { routing { get("/") { call.respondText("h1") } } }
                try {
                    val badPort = bad.localAddress.port
                    val name = "_$port._https.server.test"
                    val records = Records(mapOf(name to listOf(record(name, 1, "h3.server.test", "h3", port = badPort))))
                    val events = Events()
                    client(records.source, events).use { c ->
                        val r = c.get("https://server.test:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                        assertEquals("h1", r.bodyAsText())
                        assertEquals("h3.server.test:$badPort", withTimeout(10.seconds) { events.broken.await() })
                    }
                } finally {
                    server.stopSuspend(0, 0)
                    bad.close()
                }
            }
        }

    @Test fun networkChangeClearsCache() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val name = "_$port._https.server.test"
                val records = Records(mapOf(name to listOf(record(name, 1, ".", "h2"))))
                var network = "wifi"
                client(records.source, more = { http3 { networkId = { network } } }).use { c ->
                    c.get("https://server.test:$port/")
                    c.get("https://server.test:$port/")
                    assertEquals(1, records.asked.size, "cached: ${records.asked}")
                    network = "cellular"
                    c.get("https://server.test:$port/")
                    assertEquals(2, records.asked.size, "asked again on the new network: ${records.asked}")
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun negative_noCacheWithoutNetworkId() =
        clientTest {
            // RFC 9460 section 12: the cache MUST be partitioned per network or flushed on network changes
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val name = "_$port._https.server.test"
                val records = Records(mapOf(name to listOf(record(name, 1, ".", "h2"))))
                // without networkId the engine cannot see a network change: it keeps no answers of its own
                client(records.source).use { c ->
                    c.get("https://server.test:$port/")
                    c.get("https://server.test:$port/")
                }
                assertEquals(2, records.asked.size, "asked again: ${records.asked}")
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /** A migration hook whose [networks] are the engine's network (no `networkId`). */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    private fun following(networks: kotlinx.coroutines.flow.Flow<Any?>) =
        object : Http3ConnectionMigration {
            override fun start(
                connection: io.kuicksilver.quic.QuicConnection,
                scope: kotlinx.coroutines.CoroutineScope,
            ) = error("no HTTP/3 connection in this test")

            override val networks = networks
        }

    /**
     * RFC 9460 section 12: "Clients MUST ensure that their DNS cache is partitioned for each local network, or flushed on
     * network changes". The networks `connectionMigration` follows are a source of network changes (when `networkId` is not
     * set): answers are cached and flushed when the network changes. Before, such an engine kept no answers.
     */
    @Test fun negative_connectionMigrationNetworksFlushTheCache() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val name = "_$port._https.server.test"
                val records = Records(mapOf(name to listOf(record(name, 1, ".", "h2"))))
                val networks = kotlinx.coroutines.flow.MutableStateFlow<Any?>("wifi")
                client(records.source, more = { http3 { connectionMigration = following(networks) } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.followedNetworkUpdates.first { it >= 1 }
                    c.get("https://server.test:$port/")
                    c.get("https://server.test:$port/")
                    assertEquals(1, records.asked.size, "cached: ${records.asked}")
                    networks.value = "cellular"
                    engine.followedNetworkUpdates.first { it >= 2 }
                    c.get("https://server.test:$port/")
                    assertEquals(2, records.asked.size, "asked again on the new network: ${records.asked}")
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * Before the followed source's first value the network is unknown: a request waits a moment for it, then goes on, and
     * the HTTPS records it kept meanwhile are flushed when the value comes, since nothing says they belong to that network
     * (RFC 9460 section 12). Before, they were kept.
     */
    @Test fun negative_recordsKeptBeforeTheFirstNetworkAreFlushed() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val name = "_$port._https.server.test"
                val records = Records(mapOf(name to listOf(record(name, 1, ".", "h2"))))
                val gate = CompletableDeferred<Unit>()
                val networks =
                    kotlinx.coroutines.flow.flow<Any?> {
                        gate.await()
                        emit("wifi")
                        awaitCancellation()
                    }
                client(records.source, more = { http3 { connectionMigration = following(networks) } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    c.get("https://server.test:$port/")
                    c.get("https://server.test:$port/")
                    assertEquals(1, records.asked.size, "cached: ${records.asked}")
                    gate.complete(Unit)
                    engine.followedNetworkUpdates.first { it >= 1 }
                    c.get("https://server.test:$port/")
                    assertEquals(2, records.asked.size, "flushed at the first network: ${records.asked}")
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * RFC 9460 section 12: the cache is flushed on every update the followed source reports, also one whose value equals the
     * last (on iOS and macOS every raw update of the default path; two networks the identity cannot tell apart still
     * flush). The Alt-Svc rule looks at changed values only.
     */
    @Test fun negative_everyNetworkUpdateFlushesTheCache() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val name = "_$port._https.server.test"
                val records = Records(mapOf(name to listOf(record(name, 1, ".", "h2"))))
                val networks = kotlinx.coroutines.flow.MutableSharedFlow<Any?>(replay = 1)
                networks.emit("wifi")
                client(records.source, more = { http3 { connectionMigration = following(networks) } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.followedNetworkUpdates.first { it >= 1 }
                    c.get("https://server.test:$port/")
                    c.get("https://server.test:$port/")
                    assertEquals(1, records.asked.size, "cached: ${records.asked}")
                    networks.emit("wifi") // the same identity again
                    engine.followedNetworkUpdates.first { it >= 2 }
                    c.get("https://server.test:$port/")
                    assertEquals(2, records.asked.size, "flushed by the update: ${records.asked}")
                    networks.emit("wifi")
                    engine.followedNetworkUpdates.first { it >= 3 }
                    c.get("https://server.test:$port/")
                    assertEquals(3, records.asked.size, "and by the next one: ${records.asked}")
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /** A network source that fails leaves the engine blind to network changes: the cache is dropped and no longer kept. */
    @Test fun negative_failedNetworkSourceStopsCaching() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val name = "_$port._https.server.test"
                val records = Records(mapOf(name to listOf(record(name, 1, ".", "h2"))))
                val fail = CompletableDeferred<Unit>()
                val networks =
                    kotlinx.coroutines.flow.flow<Any?> {
                        emit("wifi")
                        fail.await()
                        throw kotlinx.io.IOException("no more network callbacks")
                    }
                client(records.source, more = { http3 { connectionMigration = following(networks) } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.followedNetworkUpdates.first { it >= 1 }
                    c.get("https://server.test:$port/")
                    c.get("https://server.test:$port/")
                    assertEquals(1, records.asked.size, "cached: ${records.asked}")
                    fail.complete(Unit)
                    engine.followedNetworkUpdates.first { it >= 2 }
                    c.get("https://server.test:$port/")
                    c.get("https://server.test:$port/")
                    assertEquals(3, records.asked.size, "no cache any more: ${records.asked}")
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun aliasChainFollowed() =
        h3Test {
            coroutineScope {
                val ep = h3Origin()
                try {
                    val port = ep.localAddress.port
                    val name = "_$port._https.server.test"
                    val records =
                        Records(
                            mapOf(
                                name to listOf(record(name, 0, "cdn.example")),
                                "cdn.example" to listOf(record("cdn.example", 0, "edge.example")),
                                "edge.example" to listOf(record("edge.example", 1, ".", "h3", port = port)),
                            ),
                        )
                    val events = Events()
                    client(records.source, events).use { c ->
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                    }
                    assertEquals(listOf(name, "cdn.example", "edge.example"), records.asked)
                    assertEquals(listOf("edge.example:$port"), events.used)
                } finally {
                    ep.close()
                }
            }
        }

    @Test fun negative_aliasLoopStops() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val name = "_$port._https.server.test"
                val records =
                    Records(
                        mapOf(
                            name to listOf(record(name, 0, "a.example")),
                            "a.example" to listOf(record("a.example", 0, "b.example")),
                            "b.example" to listOf(record("b.example", 0, "a.example")),
                        ),
                    )
                client(records.source).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://server.test:$port/").version)
                }
                assertTrue(records.asked.size <= 8, "asked ${records.asked}")
                assertEquals(listOf(name, "a.example", "b.example"), records.asked)
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun ipLiteralIsNotLookedUp() =
        clientTest {
            val (server, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("h1") } } }
            try {
                val records = Records(emptyMap())
                client(records.source).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get("https://127.0.0.1:$port/").version)
                }
                assertEquals(emptyList(), records.asked)
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun negative_extraWaitOutOfRangeFailsTheEngine() {
        for (bad in listOf((-1).seconds, 0.seconds, 49.milliseconds, 2.seconds)) { // 50 ms..1 s (RFC 9460 section 5.1)
            kotlin.test.assertFailsWith<IllegalArgumentException> {
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { httpsRecordExtraWait = bad } }).close()
            }
        }
    }

    /** An HTTP/3 server on a free UDP port of 127.0.0.1 with [identity], answering 200 "h3". */
    private suspend fun kotlinx.coroutines.CoroutineScope.h3With(identity: TlsIdentity): Http3Endpoint {
        val tls =
            tlsConfig(TlsRole.Server) {
                alpn = listOf(Http3Endpoint.H3)
                this.identity = identity
            }
        return Http3Endpoint.bind(
            InetSocketAddress("127.0.0.1", 0),
            QuicEndpointConfig.Builder().apply { server = QuicServerConfig.Builder(tls).build() }.build(),
        )
    }

    @Test fun recordCacheCountsOnTheMonotonicAndTheWallClock() {
        // ExpiryClock: neither a wall clock stepped back nor a device that slept keeps a record past its TTL
        // (HttpsRecordCacheTest pins both); here: the engine gives the cache both clocks, not the time of day alone
        client(Records(emptyMap()).source).use { c ->
            val clock = (c.engine as KuicksilverEngine).httpsRecordsForTest!!.clock
            assertTrue(clock.monotonicForTest() in 0..<getTimeMillis() / 2, "the record cache's monotonic clock is the time of day")
            val mark = clock.mark()
            assertTrue(clock.elapsedMillis(mark) in 0..60_000)
        }
    }
}
