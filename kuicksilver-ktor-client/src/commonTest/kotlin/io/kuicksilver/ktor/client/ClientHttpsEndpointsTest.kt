// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.client.dns.SvcbRecord
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.withLock
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The endpoints of SVCB resolution (RFC 9460 section 3) are where the client connects, over every transport their ALPN
 * set allows (section 7.1.2): TCP too goes to the TargetName and port, in priority order with fallback, then to the
 * origin as without records.
 */
class ClientHttpsEndpointsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun rec(
        owner: String,
        priority: Int,
        target: String,
        vararg alpn: String,
        port: Int? = null,
        noDefaultAlpn: Boolean = false,
    ) = SvcbRecord(priority, target, alpn.toList(), noDefaultAlpn, port, emptyList(), emptyList(), 300, owner)

    private val names = ArrayList<String>()
    private val namesLock = kotlinx.coroutines.sync.Mutex()

    private fun client(answers: Map<String, List<SvcbRecord>>) =
        testClient(Http3DiscoveryMode.Auto, engine = {
            resolverForTest = { host, p ->
                namesLock.withLock { names += host }
                listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p))
            }
            connectTimeout = 30.seconds
            http3 { httpsRecords = HttpsRecordsForTest { answers[it] ?: emptyList() } }
        })

    private suspend fun h1(
        body: String,
        plain: Boolean = false,
    ): Pair<TestServer, Int> =
        testServer(plain = plain, configure = {
            http3 = false
            altSvc = false
        }) { routing { get("/") { call.respondText(body) } } }

    @Test fun tcpGoesToTheRecordsTarget() =
        clientTest {
            val (origin, port) = h1("origin")
            val (target, targetPort) = h1("target")
            try {
                val name = "_$port._https.server.test"
                // alpn=h2 plus the default http/1.1: a TCP endpoint (section 7.1.2), at the record's TargetName and port
                client(mapOf(name to listOf(rec(name, 1, "svc.server.test", "h2", port = targetPort)))).use { c ->
                    val r = c.get("https://server.test:$port/")
                    assertEquals("target", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version)
                }
                assertTrue("svc.server.test" in names, "the TargetName was resolved: $names")
            } finally {
                origin.stopSuspend(0, 0)
                target.stopSuspend(0, 0)
            }
        }

    @Test fun lowerPriorityEndpointAfterAFailedOne() =
        clientTest {
            val (origin, port) = h1("origin")
            val (plain, plainPort) = h1("plain", plain = true) // TLS cannot be set up there
            val (second, secondPort) = h1("second")
            try {
                val name = "_$port._https.server.test"
                val records =
                    listOf(rec(name, 1, "a.server.test", "h2", port = plainPort), rec(name, 2, "b.server.test", "h2", port = secondPort))
                client(mapOf(name to records)).use { c -> assertEquals("second", c.get("https://server.test:$port/").bodyAsText()) }
            } finally {
                origin.stopSuspend(0, 0)
                plain.stopSuspend(0, 0)
                second.stopSuspend(0, 0)
            }
        }

    @Test fun allEndpointsFailedFallsBackToTheOrigin() =
        clientTest {
            // section 3: "the client now attempts to use non-SVCB connection modes"
            val (origin, port) = h1("origin")
            val (plain, plainPort) = h1("plain", plain = true)
            try {
                val name = "_$port._https.server.test"
                client(mapOf(name to listOf(rec(name, 1, "a.server.test", "h2", port = plainPort)))).use { c ->
                    assertEquals("origin", c.get("https://server.test:$port/").bodyAsText())
                }
            } finally {
                origin.stopSuspend(0, 0)
                plain.stopSuspend(0, 0)
            }
        }

    @Test fun aliasWithoutServiceRecordsConnectsToItsTarget() =
        clientTest {
            // section 3: the final $QNAME, the authority's port, no SvcParams (so TCP, the default ALPN set)
            val (origin, port) = h1("origin")
            try {
                val name = "_$port._https.server.test"
                client(mapOf(name to listOf(rec(name, 0, "apex.server.test")))).use { c ->
                    assertEquals("origin", c.get("https://server.test:$port/").bodyAsText())
                }
                assertTrue("apex.server.test" in names, "TCP went to the alias target: $names")
            } finally {
                origin.stopSuspend(0, 0)
            }
        }

    @Test fun negative_hangingOriginLookupDoesNotHoldUpTheRecords() =
        h3Test {
            coroutineScope {
                val ep = h3Origin()
                try {
                    val name = "_8443._https.server.test"
                    val records = listOf(rec(name, 1, "q.server.test", "h3", port = ep.localAddress.port, noDefaultAlpn = true))
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        // the origin's own addresses never come: the records alone say where to go
                        resolverForTest = { host, p ->
                            if (host == "server.test") kotlinx.coroutines.awaitCancellation()
                            listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p))
                        }
                        connectTimeout = 30.seconds
                        http3 { httpsRecords = HttpsRecordsForTest { if (it == name) records else emptyList() } }
                    }).let { c ->
                        val r = kotlinx.coroutines.withTimeout(10.seconds) { c.get("https://server.test:8443/") }
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        // the origin lookup still hangs in the background: closing the client must end it, not wait for it
                        val engine = c.engine as KuicksilverEngine
                        c.close()
                        kotlinx.coroutines.withTimeout(10.seconds) { engine.cleanup.join() }
                    }
                } finally {
                    ep.close()
                }
            }
        }

    @Test fun quicOnlyEndpointIsNotTriedOverTcp() =
        h3Test {
            coroutineScope {
                val ep = h3Origin()
                val (origin, port) = h1("origin")
                try {
                    val name = "_$port._https.server.test"
                    // no-default-alpn with alpn=h3: QUIC only (section 7.1.2), no race with TCP to that endpoint
                    val records = listOf(rec(name, 1, "q.server.test", "h3", port = ep.localAddress.port, noDefaultAlpn = true))
                    client(mapOf(name to records)).use { c ->
                        val r = c.get("https://server.test:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("h3", r.bodyAsText())
                        assertEquals(ProtocolReason.HttpsRecord, r.kuicksilverDiagnostics?.reason)
                    }
                } finally {
                    origin.stopSuspend(0, 0)
                    ep.close()
                }
            }
        }
}

/** Alt-Svc and HTTPS records together (RFC 9460 section 9.3): the alt-authority's records decide where its QUIC goes. */
class ClientHttpsAltSvcTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun rec(
        owner: String,
        priority: Int,
        target: String,
        vararg alpn: String,
        port: Int? = null,
    ) = SvcbRecord(priority, target, alpn.toList(), false, port, emptyList(), emptyList(), 300, owner)

    private class Used : KuicksilverEventListener() {
        val altSvc = ArrayList<String>()

        override fun altSvcUsed(
            request: io.ktor.client.request.HttpRequestData,
            alternative: String,
        ) {
            altSvc += alternative
        }
    }

    private fun client(
        answers: Map<String, List<SvcbRecord>>,
        store: AltSvcStore,
        used: Used,
    ) = testClient(Http3DiscoveryMode.Auto, engine = {
        resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
        connectTimeout = 30.seconds
        eventListener = used
        http3 {
            httpsRecords = HttpsRecordsForTest { answers[it] ?: emptyList() }
            altSvcStore = store
            hardDelay = kotlin.time.Duration.INFINITE // TCP only after QUIC failed: the race's outcome is QUIC's
        }
    })

    private fun storeWith(
        origin: String,
        altHost: String,
        altPort: Int,
    ) = InMemoryAltSvcStore().also {
        it.put(
            origin,
            listOf(
                AltSvcEntry(
                    "h3",
                    altHost,
                    altPort,
                    io.ktor.util.date
                        .getTimeMillis() + 3_600_000,
                    false,
                ),
            ),
        )
    }

    @Test fun altAuthorityRecordsGiveTheQuicTarget() =
        h3Test {
            coroutineScope {
                val q = h3Origin()
                val (origin, port) =
                    testServer(configure = {
                        http3 = false
                        altSvc = false
                    }) { routing { get("/") { call.respondText("origin") } } }
                try {
                    // the alternative alt.server.test:<port> has no QUIC listener; its HTTPS record moves it to q's port
                    val alt = "_$port._https.alt.server.test"
                    val used = Used()
                    client(
                        mapOf(alt to listOf(rec(alt, 1, "q.server.test", "h3", port = q.localAddress.port))),
                        storeWith("https://server.test:$port", "alt.server.test", port),
                        used,
                    ).use { c ->
                        val r = c.get("https://server.test:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("h3", r.bodyAsText())
                    }
                    assertEquals(listOf("q.server.test:${q.localAddress.port}"), used.altSvc)
                } finally {
                    origin.stopSuspend(0, 0)
                    q.close()
                }
            }
        }

    @Test fun negative_altAuthorityWithoutH3IsNotUsed() =
        clientTest {
            // section 9.3: no ALPN consistent with both the record and Alt-Svc: no connection to the alternative
            val (origin, port) =
                testServer(configure = {
                    http3 = false
                    altSvc = false
                }) { routing { get("/") { call.respondText("origin") } } }
            try {
                val alt = "_$port._https.alt.server.test"
                val used = Used()
                client(
                    mapOf(alt to listOf(rec(alt, 1, "alt2.server.test", "h2"))),
                    storeWith("https://server.test:$port", "alt.server.test", port),
                    used,
                ).use { c ->
                    val r = c.get("https://server.test:$port/")
                    assertEquals("origin", r.bodyAsText())
                }
                assertEquals(emptyList(), used.altSvc)
            } finally {
                origin.stopSuspend(0, 0)
            }
        }
}
