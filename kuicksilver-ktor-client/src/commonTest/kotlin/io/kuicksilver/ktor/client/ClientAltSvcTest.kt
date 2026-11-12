// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class ClientAltSvcTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun autoUpgradesToH3AfterAltSvc() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("used=${call.request.headers["Alt-Used"]}") } } }
            try {
                testClient(Http3DiscoveryMode.Auto).use { c ->
                    val first = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, first.version)
                    assertEquals("used=null", first.bodyAsText())
                    // the second request races HTTP/3 against the pooled HTTP/1.1 connection (no head start on a network where QUIC
                    // was not seen working yet): HTTP/1.1 wins on loopback, the QUIC connection set up meanwhile serves the next ones
                    c.get("https://127.0.0.1:$port/").bodyAsText()
                    val engine = c.engine as KuicksilverEngine
                    kotlinx.coroutines.withTimeout(5.seconds) {
                        while (!engine.hasH3Connection(io.ktor.http.Url("https://127.0.0.1:$port/"))) kotlinx.coroutines.delay(20)
                    }
                    val third = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, third.version)
                    assertEquals("used=127.0.0.1:$port", third.bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** A request cancelled while its Alt-Svc write waits behind another still gets the write done (it is not lost with the caller). */
    @Test fun deferredAltSvcWriteSurvivesCancellation() =
        h3Test {
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "h3=\":${call.request.local.localPort}\"")
                            call.respondText("h1")
                        }
                    }
                }
            val path = kotlinx.io.files.Path(kotlinx.io.files.SystemTemporaryDirectory, "altsvc-${kotlin.random.Random.nextLong()}.tsv")
            try {
                val store = FileAltSvcStore(path)
                val origin = "https://127.0.0.1:$port"
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { altSvcStore = store } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.altSvcWriteLock.lock() // the next write waits here
                    val request = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch { c.get("$origin/") }
                    kotlinx.coroutines.withTimeout(5.seconds) {
                        while (engine.altSvcSnapshot(io.ktor.http.Url("$origin/")).isEmpty()) kotlinx.coroutines.delay(10)
                    }
                    request.cancel()
                    request.join()
                    engine.altSvcWriteLock.unlock()
                    kotlinx.coroutines.withTimeout(5.seconds) {
                        while (FileAltSvcStore(path).get(origin).isEmpty()) kotlinx.coroutines.delay(10)
                    }
                }
            } finally {
                server.stop(100, 500)
                kotlinx.io.files.SystemFileSystem
                    .delete(path, mustExist = false)
            }
        }

    /**
     * On a network change the engine forgets the alternatives without `persist=1` by default (RFC 7838 section 2.2:
     * "clients SHOULD remove from cache all alternative services that lack the persist flag"); before, it did so only
     * with `clearOnNetworkChange = true`. A persistent one stays, and `clearOnNetworkChange = false` still keeps both.
     */
    @Test fun networkChangeForgetsNonPersistentAlternativesByDefault() =
        clientTest {
            var served = 0
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            // only the first response of each client advertises alternatives
                            if (served++ % 2 == 0) {
                                val p = call.request.local.localPort
                                call.response.header("Alt-Svc", "h3=\":$p\", h3=\":${p + 1}\"; persist=1")
                            }
                            call.respondText("h1")
                        }
                    }
                }
            try {
                val origin = io.ktor.http.Url("https://127.0.0.1:$port/")
                for (clear in listOf(null, false)) {
                    var network = "a"
                    // Auto: the client records Alt-Svc (nothing listens for QUIC there, so requests fall back to HTTP/1.1)
                    testClient(
                        Http3DiscoveryMode.Auto,
                        engine = {
                            http3 {
                                networkId = { network }
                                if (clear != null) clearOnNetworkChange = clear
                            }
                        },
                    ).use { c ->
                        val engine = c.engine as KuicksilverEngine
                        c.get(origin).bodyAsText()
                        assertEquals(2, engine.altSvcSnapshot(origin).size)
                        network = "b"
                        c.get(origin).bodyAsText()
                        val left = engine.altSvcSnapshot(origin)
                        if (clear == null) assertEquals(listOf(port + 1), left.map { it.port }) else assertEquals(2, left.size)
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The per-origin RTT memory is bounded like the Alt-Svc cache (threat-model 3.18). */
    @Test fun srttMapBounded() =
        clientTest {
            testClient(Http3DiscoveryMode.Auto).use { c ->
                val engine = c.engine as KuicksilverEngine
                repeat(AltSvcCache.MAX_ORIGINS + 50) { engine.rememberSrtt("https://o$it.test:443", 10.milliseconds) }
                assertEquals(AltSvcCache.MAX_ORIGINS, engine.srttOrigins)
            }
        }

    @Test fun plainHttpAltSvcIgnored() =
        clientTest {
            val (server, port) =
                testServer(plain = true) {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "h3=\":8443\"")
                            call.respondText("plain")
                        }
                    }
                }
            try {
                val store = InMemoryAltSvcStore()
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { altSvcStore = store } }).use { c ->
                    c.get("http://127.0.0.1:$port/").bodyAsText()
                    assertTrue(store.get("http://127.0.0.1:$port").isEmpty() && store.get("https://127.0.0.1:$port").isEmpty())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** RFC 7838 section 3: an `Alt-Svc: clear` over HTTP/1.1 removes a cached alternative even while one is cached and failing. */
    @Test fun clearOverH1RemovesCachedAlternative() =
        clientTest {
            var calls = 0
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            calls++
                            call.response.header(
                                "Alt-Svc",
                                if (calls ==
                                    1
                                ) {
                                    "h3=\":${call.request.local.localPort}\""
                                } else {
                                    "clear"
                                },
                            )
                            call.respondText("h1")
                        }
                    }
                }
            try {
                val store = InMemoryAltSvcStore()
                val origin = "https://127.0.0.1:$port"
                testClient(Http3DiscoveryMode.Auto, engine = {
                    http3 { altSvcStore = store }
                    quic =
                        io.kuicksilver.quic.quicConfig { handshakeTimeout = kotlin.time.Duration.parse("500ms") }
                }).use { c ->
                    assertEquals("h1", c.get("$origin/").bodyAsText())
                    assertTrue(store.get(origin).isNotEmpty(), "the alternative was learned")
                    val second = c.get("$origin/")
                    // the UDP side answers nothing: HTTP/1.1 served it, and that response said `clear`
                    assertEquals(HttpProtocolVersion.HTTP_1_1, second.version)
                    assertTrue(store.get(origin).isEmpty(), "clear over HTTP/1.1 removed the alternative: ${store.get(origin)}")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 7838 section 6 removes an alternative only for a 421 from that alternative: a 421 from the origin itself over
     * HTTP/1.1 (RFC 9110 section 15.5.20, a response that is not authoritative for the origin) leaves the cache unchanged.
     */
    @Test fun misdirectedOverH1KeepsCachedAlternative() =
        clientTest {
            var calls = 0
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            calls++
                            if (calls == 1) {
                                call.response.header("Alt-Svc", "h3=\":${call.request.local.localPort}\"")
                                call.respondText("h1")
                            } else {
                                call.response.header("Alt-Svc", "clear")
                                call.respondText("elsewhere", status = HttpStatusCode.fromValue(421))
                            }
                        }
                    }
                }
            try {
                val store = InMemoryAltSvcStore()
                val origin = "https://127.0.0.1:$port"
                testClient(Http3DiscoveryMode.Auto, engine = {
                    http3 { altSvcStore = store }
                    quic =
                        io.kuicksilver.quic.quicConfig { handshakeTimeout = kotlin.time.Duration.parse("500ms") }
                }).use { c ->
                    assertEquals("h1", c.get("$origin/").bodyAsText())
                    val learned = store.get(origin)
                    assertTrue(learned.isNotEmpty(), "the alternative was learned")
                    val second = c.get("$origin/")
                    assertEquals(HttpProtocolVersion.HTTP_1_1, second.version)
                    assertEquals(421, second.status.value)
                    assertEquals(learned, store.get(origin), "a 421 from the origin left the alternative cached")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 7838 section 2.4: a client "SHOULD use that alternative service for all requests to the associated origin as soon as
     * it is available, provided the alternative service information is fresh", and after a failure "MAY fall back to using
     * the origin or another alternative service". A broken mark on the first cached alternative sends the request to the
     * next fresh one that is not broken; before, it went straight to TCP although a second alternative was cached.
     */
    @Test fun negative_brokenFirstAlternativeUsesTheNextOne() =
        h3Test {
            val (server, port) = testServer(configure = { altSvc = false }) { routing { get("/") { call.respondText("ok") } } }
            try {
                val origin = "https://127.0.0.1:$port"
                val far =
                    io.ktor.util.date
                        .getTimeMillis() + 3_600_000
                val store = InMemoryAltSvcStore()
                store.put(origin, listOf(AltSvcEntry("h3", null, 1, far, false), AltSvcEntry("h3", null, port, far, false)))
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { altSvcStore = store } }).use { c ->
                    (c.engine as KuicksilverEngine).brokenAltSvc.markBroken(origin, "127.0.0.1:1")
                    val d = c.get("$origin/").kuicksilverDiagnostics!!
                    assertEquals("127.0.0.1:$port", d.alternative, "$d")
                    assertEquals(null, d.brokenSince, "$d")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 7838 section 9.4: "In a user agent, any alternative service information MUST be removed when origin-specific data
     * is cleared (typically, when cookies [RFC6265] are cleared)." `clearAlternativeServices(origin)` forgets that origin's
     * alternatives (in the store, on disk too), its broken marks and its RTT; without an origin, everything. Before, there
     * was no supported way: the store was mutated under the engine's lock only.
     */
    @Test fun negative_clearAlternativeServicesRemovesOriginData() =
        clientTest {
            val (server, port) =
                testServer(configure = { http3 = false }) {
                    routing {
                        get("/") {
                            call.response.header("Alt-Svc", "h3=\":${call.request.local.localPort}\"; persist=1")
                            call.respondText("h1")
                        }
                    }
                }
            val path = kotlinx.io.files.Path(kotlinx.io.files.SystemTemporaryDirectory, "altsvc-${kotlin.random.Random.nextLong()}.tsv")
            try {
                val origin = "https://127.0.0.1:$port"
                val other = "https://other.example:443"
                val store = FileAltSvcStore(path)
                store.put(
                    other,
                    listOf(
                        AltSvcEntry(
                            "h3",
                            null,
                            443,
                            io.ktor.util.date
                                .getTimeMillis() + 60_000,
                            true,
                        ),
                    ),
                )
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { altSvcStore = store } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    c.get("$origin/").bodyAsText()
                    assertEquals(listOf(port), engine.altSvcSnapshot(io.ktor.http.Url("$origin/")).map { it.port })
                    engine.brokenAltSvc.markBroken(origin, "127.0.0.1:$port")
                    engine.brokenAltSvc.markBroken(other, "other.example:443")
                    engine.rememberSrtt(origin, 10.milliseconds)
                    engine.rememberSrtt(other, 10.milliseconds)

                    c.clearAlternativeServices(io.ktor.http.Url("$origin/"))
                    assertTrue(engine.altSvcSnapshot(io.ktor.http.Url("$origin/")).isEmpty())
                    assertTrue(FileAltSvcStore(path).get(origin).isEmpty(), "removed on disk too")
                    assertEquals(1, FileAltSvcStore(path).get(other).size, "another origin is kept")
                    assertEquals(null, engine.brokenAltSvc.brokenReason(origin, "127.0.0.1:$port"))
                    assertTrue(engine.brokenAltSvc.brokenReason(other, "other.example:443") != null)
                    assertEquals(1, engine.srttOrigins)

                    c.clearAlternativeServices()
                    assertTrue(FileAltSvcStore(path).get(other).isEmpty(), "everything removed on disk")
                    assertTrue(store.get(other).isEmpty())
                    assertEquals(0, engine.brokenAltSvc.size)
                    assertEquals(0, engine.srttOrigins)
                }
            } finally {
                server.stop(100, 500)
                kotlinx.io.files.SystemFileSystem
                    .delete(path, mustExist = false)
            }
        }

    /** A server whose first response to each client advertises one alternative without `persist` and one with it. */
    private suspend fun advertisingOnce() =
        testServer(configure = { http3 = false }) {
            var served = 0
            routing {
                get("/") {
                    if (served++ == 0) {
                        val p = call.request.local.localPort
                        call.response.header("Alt-Svc", "h3=\":$p\", h3=\":${p + 1}\"; persist=1")
                    }
                    call.respondText("h1")
                }
            }
        }

    /**
     * RFC 7838 section 2.2: "clients SHOULD remove from cache all alternative services that lack the "persist" flag with the
     * value "1" when they detect such a change, when information about network state is available"; section 3.1: "By
     * default, cached alternative services will be cleared when the client detects a network change." A [FileAltSvcStore]
     * keeps the network its alternatives were learned on: an engine started on another network forgets the non-persistent
     * ones at its first request, one on the same network keeps them. Before, every reloaded entry was used until `ma`.
     */
    @Test fun negative_networkChangeAcrossRestartForgetsNonPersistent() =
        clientTest {
            val (server, port) = advertisingOnce()
            val path = kotlinx.io.files.Path(kotlinx.io.files.SystemTemporaryDirectory, "altsvc-${kotlin.random.Random.nextLong()}.tsv")
            try {
                val url = io.ktor.http.Url("https://127.0.0.1:$port/")

                fun client(network: String) =
                    testClient(Http3DiscoveryMode.Auto, engine = {
                        http3 {
                            altSvcStore = FileAltSvcStore(path)
                            networkId = { network }
                        }
                    })
                client("wifi").use { c ->
                    c.get(url).bodyAsText()
                    assertEquals(2, (c.engine as KuicksilverEngine).altSvcSnapshot(url).size)
                }
                client("wifi").use { c ->
                    c.get(url).bodyAsText()
                    assertEquals(2, (c.engine as KuicksilverEngine).altSvcSnapshot(url).size, "same network: both kept")
                }
                client("cellular").use { c ->
                    c.get(url).bodyAsText()
                    assertEquals(listOf(port + 1), (c.engine as KuicksilverEngine).altSvcSnapshot(url).map { it.port })
                }
                assertEquals(listOf(port + 1), FileAltSvcStore(path).get("https://127.0.0.1:$port").map { it.port })
            } finally {
                server.stop(100, 500)
                kotlinx.io.files.SystemFileSystem
                    .delete(path, mustExist = false)
            }
        }

    /**
     * With `connectionMigration` the engine has information about network state (RFC 7838 section 2.2): when `networkId` is
     * not set, the hook's own source of networks is the network, and a change forgets the non-persistent alternatives (and
     * broken marks) as a `networkId` change does. Before, a migration reached nothing but the connections.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_connectionMigrationNetworkChangeForgetsNonPersistent() =
        clientTest {
            val (server, port) = advertisingOnce()
            try {
                val url = io.ktor.http.Url("https://127.0.0.1:$port/")
                val networks = kotlinx.coroutines.flow.MutableStateFlow<Any?>("wifi")
                val migration =
                    object : Http3ConnectionMigration {
                        override fun start(
                            connection: io.kuicksilver.quic.QuicConnection,
                            scope: kotlinx.coroutines.CoroutineScope,
                        ) = error("no HTTP/3 connection in this test")

                        override val networks = networks
                    }
                testClient(Http3DiscoveryMode.Auto, engine = { http3 { connectionMigration = migration } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.followedNetworkUpdates.first { it >= 1 }
                    c.get(url).bodyAsText()
                    assertEquals(2, engine.altSvcSnapshot(url).size)
                    engine.brokenAltSvc.markBroken("https://127.0.0.1:$port", "127.0.0.1:$port")
                    networks.value = "cellular"
                    engine.followedNetworkUpdates.first { it >= 2 }
                    assertEquals(listOf(port + 1), engine.altSvcSnapshot(url).map { it.port })
                    assertEquals(null, engine.brokenAltSvc.brokenReason("https://127.0.0.1:$port", "127.0.0.1:$port"))
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 7838 section 4: "Receiving an ALTSVC frame is semantically equivalent to receiving an Alt-Svc header field." A
     * server that follows section 3 ("When using HTTP/2 ([RFC7540]), servers SHOULD instead send an ALTSVC frame") sends
     * the frame (the Kuicksilver server the field too): the client learns the alternative from the frame. Before, the frame
     * was skipped as unknown and nothing was learned from it.
     */
    @Test fun negative_altSvcFrameOverH2IsLearned() =
        h3Test {
            val (server, port) = testServer(configure = { http2 = true }) { routing { get("/") { call.respondText("ok") } } }
            try {
                val url = io.ktor.http.Url("https://127.0.0.1:$port/")
                testClient(Http3DiscoveryMode.Auto).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val r = c.get(url)
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    engine.altSvcFramesApplied.first { it >= 1 }
                    assertEquals(listOf(port), engine.altSvcSnapshot(url).map { it.port })
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * ALTSVC frames are learned by one coroutine, the last frame of an origin winning: an `h3` followed by a `clear` ends
     * cleared, whatever the scheduling, and a flood waits as at most one value per origin (bounded by the origins kept),
     * not as a coroutine per frame. Before, every frame launched its own coroutine, unbounded and in no order.
     */
    @Test fun negative_altSvcFramesLearnedInOrderAndBounded() =
        clientTest {
            testClient(Http3DiscoveryMode.Auto).use { c ->
                val engine = c.engine as KuicksilverEngine
                val url = io.ktor.http.Url("https://example.com/")
                repeat(5_000) {
                    engine.onAltSvcFrame(url, "h3=\":443\"")
                    engine.onAltSvcFrame(url, "clear")
                    assertTrue(engine.altSvcFramesWaiting <= 1, "one value per origin waits")
                }
                engine.altSvcFramesApplied.first { it >= engine.altSvcFramesReceived }
                assertTrue(engine.altSvcSnapshot(url).isEmpty(), "the last frame, clear, holds")
                engine.onAltSvcFrame(url, "h3=\":443\"")
                engine.altSvcFramesApplied.first { it >= engine.altSvcFramesReceived }
                assertEquals(listOf(443), engine.altSvcSnapshot(url).map { it.port })
                repeat(AltSvcCache.MAX_ORIGINS + 500) { engine.onAltSvcFrame(io.ktor.http.Url("https://o$it.example/"), "clear") }
                assertTrue(engine.altSvcFramesWaiting <= AltSvcCache.MAX_ORIGINS, "${engine.altSvcFramesWaiting} waiting")
                engine.altSvcFramesApplied.first { it >= engine.altSvcFramesReceived }
            }
        }

    /** A hook whose [networks] are the engine's network (no `networkId`); it never migrates (no HTTP/3 here). */
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
     * A followed network has no identity that survives a restart (an Android network handle is a number the system reuses
     * after a reboot, an Apple path key names an interface, not the network behind it): it is never stored, and at its
     * first value the engine takes the network as changed (RFC 7838 section 2.2), so alternatives without `persist=1`
     * reloaded from a store are dropped even when the source reports the same text as before.
     */
    @Test fun negative_followedNetworkIsNotTrustedAcrossRestarts() =
        clientTest {
            val path = kotlinx.io.files.Path(kotlinx.io.files.SystemTemporaryDirectory, "altsvc-${kotlin.random.Random.nextLong()}.tsv")
            try {
                val origin = "https://example.com:443"
                val far =
                    io.ktor.util.date
                        .getTimeMillis() + 3_600_000
                FileAltSvcStore(path).put(origin, listOf(AltSvcEntry("h3", null, 443, far, false), AltSvcEntry("h3", null, 444, far, true)))
                val store = FileAltSvcStore(path)
                testClient(Http3DiscoveryMode.Auto, engine = {
                    http3 {
                        altSvcStore = store
                        connectionMigration = following(kotlinx.coroutines.flow.MutableStateFlow<Any?>("100"))
                    }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    engine.followedNetworkUpdates.first { it >= 1 }
                    assertEquals(listOf(444), engine.altSvcSnapshot(io.ktor.http.Url("$origin/")).map { it.port })
                }
                assertEquals(null, FileAltSvcStore(path).networkId, "a followed network is not stored")
            } finally {
                kotlinx.io.files.SystemFileSystem
                    .delete(path, mustExist = false)
            }
        }

    /**
     * A store that throws while a network change is applied (an application's own `AltSvcStore`) loses that change, not the
     * following of the network: the next change still reaches the store. Before, the exception ended the follower for good.
     */
    @Test fun negative_failingStoreDoesNotStopNetworkFollowing() =
        clientTest {
            var calls = 0
            val inner = InMemoryAltSvcStore()
            val store =
                object : AltSvcStore by inner {
                    override fun clearNonPersistent() {
                        if (++calls == 1) throw IllegalStateException("database locked")
                        inner.clearNonPersistent()
                    }
                }
            val networks = kotlinx.coroutines.flow.MutableStateFlow<Any?>("wifi")
            testClient(Http3DiscoveryMode.Auto, engine = {
                http3 {
                    altSvcStore = store
                    connectionMigration = following(networks)
                }
            }).use { c ->
                val engine = c.engine as KuicksilverEngine
                engine.followedNetworkUpdates.first { it >= 1 }
                assertEquals(1, calls)
                networks.value = "cellular"
                engine.followedNetworkUpdates.first { it >= 2 }
                assertEquals(2, calls, "the next change was applied")
            }
        }

    /**
     * Broken marks live in memory only, so they run on a monotonic clock: a step of the wall clock can neither extend nor
     * cut a mark's backoff. Before, the engine gave them the wall clock (epoch milliseconds).
     */
    @Test fun negative_brokenMarksRunOnAMonotonicClock() =
        clientTest {
            testClient(Http3DiscoveryMode.Auto).use { c ->
                val clock = (c.engine as KuicksilverEngine).brokenAltSvc.clock
                assertTrue(clock() < 3_600_000, "a monotonic clock from the engine's start, not epoch time: ${clock()}")
            }
        }
}
