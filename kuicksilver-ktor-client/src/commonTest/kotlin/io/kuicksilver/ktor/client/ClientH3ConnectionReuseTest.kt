// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.request.url
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.request.httpVersion
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.ktor.client.h3.H3Target
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.PreferredAddress
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * How the HTTP/3 pool meets RFC 9114 section 3.3: "Clients SHOULD NOT open more than one HTTP/3 connection to a given IP
 * address and UDP port [...]. A client MAY open multiple HTTP/3 connections to the same IP address and UDP port using
 * different transport or TLS configurations but SHOULD avoid creating multiple connections with the same configuration."
 * The pool keys a connection by its origin host (the TLS server_name and reference identity: its TLS configuration) and
 * the UDP destination's name and port (docs/spec/rfc/9114.md, section 3.3).
 */
class ClientH3ConnectionReuseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Every name resolves to 127.0.0.1: the server's certificate names `server.test` and `*.wild.test`. */
    private fun client() =
        testClient(Http3DiscoveryMode.H3Only, engine = {
            resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
        })

    /** One origin, one configuration: every request shares one connection to the address and port. */
    @Test fun sameOriginSharesOneConnection() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                client().use { c ->
                    repeat(5) {
                        val r = c.get("https://server.test:$port/")
                        assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                        assertEquals("ok", r.bodyAsText())
                    }
                    assertEquals(1, (c.engine as KuicksilverEngine).h3.connectionsForTest().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Two origins at one address and port: a connection each, with a TLS configuration each (server_name and the name the
     * certificate is checked against), the case the section's MAY covers. No connection is reused across origins (RFC 9114
     * section 3.3 makes that a MAY too; ADR-0017).
     */
    @Test fun negative_originsAtOneAddressGetAConnectionAndTlsConfigurationEach() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                client().use { c ->
                    for (origin in listOf("https://server.test:$port/", "https://a.wild.test:$port/", "https://server.test:$port/")) {
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(origin).version)
                    }
                    val conns = (c.engine as KuicksilverEngine).h3.connectionsForTest()
                    assertEquals(2, conns.size, "one per origin")
                    val remotes =
                        conns.map {
                            it.quic.paths
                                .first()
                                .remoteAddress.port
                        }
                    assertTrue(remotes.all { it == port }, "both to 127.0.0.1:$port: $remotes")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A server that announces [first] (an `Alt-Svc` value) until [switch] completes, then [second]; HTTP/3 responses carry
     * it too, so the client learns the second over HTTP/3. Returns the server, its port and the `Alt-Used` of each HTTP/3
     * request it served.
     */
    private suspend fun advertisingServer(
        first: (Int) -> String,
        second: (Int) -> String,
        switch: kotlinx.coroutines.CompletableDeferred<Unit>,
    ): Triple<TestServer, Int, kotlinx.coroutines.channels.Channel<String>> {
        val altUsed = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        var port = 0
        val (server, p) =
            testServer(configure = { altSvc = false }) {
                routing {
                    get("/") {
                        if (call.request.httpVersion == "HTTP/3") altUsed.trySend(call.request.headers["alt-used"] ?: "")
                        call.response.header("Alt-Svc", if (switch.isCompleted) second(port) else first(port))
                        call.respondText("ok")
                    }
                }
            }
        port = p
        return Triple(server, p, altUsed)
    }

    /** Requests [url] until one goes over HTTP/3 with `Alt-Used` [expected] (the race may give the first to HTTP/1.1). */
    private suspend fun untilAlternativeUsed(
        c: io.ktor.client.HttpClient,
        url: String,
        altUsed: kotlinx.coroutines.channels.Channel<String>,
        expected: String,
    ) = kotlinx.coroutines.withTimeout(20.seconds) {
        while (true) {
            if (c.get(url).version == HttpProtocolVersion.HTTP_3_0 && altUsed.receive() == expected) break
        }
    }

    private fun autoClient(resolve: (String) -> List<TcpAddress>) =
        testClient(Http3DiscoveryMode.Auto, engine = {
            resolverForTest = { host, p -> resolve(host).map { TcpAddress(it.bytes, p) } }
            http3 { altSvcStore = InMemoryAltSvcStore() }
        })

    private val loopback = TcpAddress(byteArrayOf(127, 0, 0, 1), 0)

    /**
     * RFC 9114 section 3.3: "Clients SHOULD NOT open more than one HTTP/3 connection to a given IP address and UDP port,
     * where the IP address and port might be derived from [...] a selected alternative service". The origin's own host
     * and an `Alt-Svc` alternative under another name resolve to one address and port: the alternative's requests go over
     * the connection the origin's host already has, with the same TLS configuration (the origin's).
     */
    @Test fun alternativeUnderAnotherNameOfTheSameAddressReusesTheConnection() =
        h3Test {
            val switch = kotlinx.coroutines.CompletableDeferred<Unit>()
            val (server, port, altUsed) = advertisingServer({ "h3=\":$it\"" }, { "h3=\"alias.test:$it\"" }, switch)
            try {
                autoClient { listOf(loopback) }.use { c ->
                    val url = "https://server.test:$port/"
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get(url).version) // learns h3=":port"
                    untilAlternativeUsed(c, url, altUsed, "server.test:$port")
                    switch.complete(Unit)
                    untilAlternativeUsed(c, url, altUsed, "alias.test:$port")
                    val h3 = (c.engine as KuicksilverEngine).h3
                    assertEquals(
                        1,
                        h3.connectionsForTest().size,
                        "one connection to 127.0.0.1:$port: shared ${h3.sharedForTest.load()} " +
                            h3.connectionsForTest().map { it.quic.paths.map { p -> p.remoteAddress } },
                    )
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The same with an address literal: an origin on 127.0.0.1 and its alternative `localhost`, which resolves there. */
    @Test fun alternativeNameOfTheOriginsAddressLiteralReusesTheConnection() =
        h3Test {
            val switch = kotlinx.coroutines.CompletableDeferred<Unit>()
            val (server, port, altUsed) = advertisingServer({ "h3=\":$it\"" }, { "h3=\"localhost:$it\"" }, switch)
            try {
                autoClient { listOf(loopback) }.use { c ->
                    val url = "https://127.0.0.1:$port/"
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get(url).version)
                    untilAlternativeUsed(c, url, altUsed, "127.0.0.1:$port")
                    switch.complete(Unit)
                    untilAlternativeUsed(c, url, altUsed, "localhost:$port")
                    assertEquals(1, (c.engine as KuicksilverEngine).h3.connectionsForTest().size)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Compared with the address the connection really uses: an alternative whose name resolves elsewhere (127.0.0.2, where
     * nothing answers) is not sent over the origin's connection; its own attempt fails and the request falls back.
     */
    @Test fun negative_alternativeOfAnotherAddressIsNotReused() =
        h3Test {
            val switch = kotlinx.coroutines.CompletableDeferred<Unit>()
            val (server, port, altUsed) = advertisingServer({ "h3=\":$it\"" }, { "h3=\"elsewhere.test:$it\"" }, switch)
            try {
                val elsewhere = TcpAddress(byteArrayOf(127, 0, 0, 2), 0)
                autoClient { if (it == "elsewhere.test") listOf(elsewhere) else listOf(loopback) }.use { c ->
                    val url = "https://server.test:$port/"
                    assertEquals(HttpProtocolVersion.HTTP_1_1, c.get(url).version)
                    untilAlternativeUsed(c, url, altUsed, "server.test:$port")
                    switch.complete(Unit)
                    c.get(url) // learns elsewhere.test
                    val r = c.get(url)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, r.version, "not over the connection to 127.0.0.1")
                    assertTrue(altUsed.tryReceive().getOrNull() != "elsewhere.test:$port")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A setup of the origin still in its handshake is waited for one Connection Attempt Delay at most: one that stalls (a
     * black-holed alternative) does not hold another destination of the origin up for its whole connect timeout.
     */
    @Test fun negative_aStalledSiblingSetupHoldsAnotherDestinationOnlyBriefly() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
                    connectTimeout = 60.seconds
                }).use { c ->
                    val h3 = (c.engine as KuicksilverEngine).h3
                    val setups = kotlin.concurrent.atomics.AtomicInt(0)
                    val inSetup = kotlinx.coroutines.CompletableDeferred<Unit>()
                    val stalled = kotlinx.coroutines.CompletableDeferred<Unit>()
                    h3.beforeSetupForTest = {
                        if (setups.addAndFetch(1) == 1) {
                            inSetup.complete(Unit)
                            stalled.await()
                        }
                    }
                    val data =
                        io.ktor.client.request
                            .HttpRequestBuilder()
                            .apply { url("https://server.test:$port/") }
                            .build()
                    kotlinx.coroutines.coroutineScope {
                        val first = async { h3.connection(H3Target("server.test", "server.test", port), data) }
                        inSetup.await()
                        val second = withTimeout(10.seconds) { h3.connection(H3Target("server.test", "alias.test", port), data) }
                        assertTrue(!second.closed.isCompleted)
                        stalled.complete(Unit)
                        first.await()
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Two destinations of one origin set up at once, each handshake slower than the Connection Attempt Delay, so neither
     * finds the other's address in time: the setup that finishes second finds the first's connection at the same address
     * and port, closes its own before any request used it, and hands its callers the first's. Both requests complete, on
     * one connection.
     */
    @Test fun negative_concurrentSetupsToOneAddressEndOnOneConnection() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    resolverForTest = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }
                    connectTimeout = 30.seconds
                }).use { c ->
                    val h3 = (c.engine as KuicksilverEngine).h3
                    val setups = kotlin.concurrent.atomics.AtomicInt(0)
                    val bothStarted = kotlinx.coroutines.CompletableDeferred<Unit>()
                    h3.beforeSetupForTest = {
                        if (setups.addAndFetch(1) == 2) bothStarted.complete(Unit)
                        bothStarted.await() // each handshake waits until the other one started too
                    }
                    val data =
                        io.ktor.client.request
                            .HttpRequestBuilder()
                            .apply { url("https://server.test:$port/") }
                            .build()
                    val bodies =
                        kotlinx.coroutines.coroutineScope {
                            listOf(H3Target("server.test", "server.test", port), H3Target("server.test", "alias.test", port))
                                .map { t ->
                                    async {
                                        val call = kotlinx.coroutines.Job(coroutineContext[kotlinx.coroutines.Job])
                                        try {
                                            val r = h3.execute(t, data, coroutineContext + call)
                                            (r.body as io.ktor.utils.io.ByteReadChannel)
                                                .readBuffer()
                                                .readByteArray()
                                                .decodeToString()
                                        } finally {
                                            call.complete()
                                        }
                                    }
                                }.map { it.await() }
                        }
                    assertEquals(listOf("ok", "ok"), bodies)
                    assertEquals(2, setups.load(), "both destinations started a handshake")
                    assertEquals(1, h3.connectionsForTest().size, "one connection to 127.0.0.1:$port")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A connection the server moved to its preferred address (RFC 9000 section 9.6) is compared by that address from then
     * on: a new destination of the origin resolving there shares it.
     */
    @Test fun destinationAtTheServersPreferredAddressReusesTheMovedConnection() =
        h3Test {
            // a free UDP port number for the preferred address: bound once by a throwaway endpoint, then released
            val prefPort =
                Http3Endpoint
                    .bind(InetSocketAddress("127.0.0.1", 0))
                    .let { ep -> ep.localAddress.port.also { ep.closeAndJoin() } }
            val tls =
                tlsConfig(TlsRole.Server) {
                    alpn = listOf(Http3Endpoint.H3)
                    identity = ClientFixtures.identity()
                }
            val server =
                Http3Endpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig
                                    .Builder(tls)
                                    .apply {
                                        preferredAddress =
                                            PreferredAddress(
                                                InetSocketAddress("127.0.0.1", prefPort),
                                                null,
                                            )
                                    }.build()
                        }.build(),
                )
            val port = server.localAddress.port
            kotlinx.coroutines.coroutineScope {
                val serving =
                    launch {
                        while (true) {
                            val conn = server.accept()
                            launch {
                                runCatching {
                                    while (true) {
                                        val r = conn.acceptRequest()
                                        r.respond(200, Http3Headers.of("content-length" to "2")).apply {
                                            output.writeFully("ok".encodeToByteArray())
                                            finish()
                                        }
                                    }
                                }
                            }
                        }
                    }
                try {
                    client().use { c ->
                        val h3 = (c.engine as KuicksilverEngine).h3
                        assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                        val conn = h3.connectionsForTest().single()
                        withTimeout(10.seconds) {
                            // the client moves after the handshake and the pool learns the new address from the path change
                            while (h3.preferredMovesForTest.load() == 0) kotlinx.coroutines.yield()
                        }
                        assertEquals(
                            prefPort,
                            conn.quic.paths
                                .single()
                                .remoteAddress.port,
                        )
                        val data =
                            io.ktor.client.request
                                .HttpRequestBuilder()
                                .apply { url("https://server.test:$port/") }
                                .build()
                        val shared = h3.connection(H3Target("server.test", "alias.test", prefPort), data)
                        assertTrue(shared === conn, "the moved connection is shared")
                        assertEquals(1, h3.connectionsForTest().size)
                    }
                } finally {
                    serving.cancel()
                    server.close()
                }
            }
        }

    /** The zone is part of a destination: one link-local address on two interfaces is two destinations. */
    @Test fun negative_linkLocalAddressesOfTwoZonesDiffer() {
        val ll =
            ByteArray(16).also {
                it[0] = 0xfe.toByte()
                it[1] = 0x80.toByte()
                it[15] = 1
            }
        val a =
            io.kuicksilver.ktor.client.h3.Destination
                .of(TcpAddress(ll, 443, scopeId = 1))
        assertTrue(
            a.sameAs(
                io.kuicksilver.ktor.client.h3.Destination
                    .of(TcpAddress(ll, 443, scopeId = 1)),
            ),
        )
        assertTrue(
            !a.sameAs(
                io.kuicksilver.ktor.client.h3.Destination
                    .of(TcpAddress(ll, 443, scopeId = 2)),
            ),
            "another interface",
        )
        assertTrue(
            !a.sameAs(
                io.kuicksilver.ktor.client.h3.Destination
                    .of(TcpAddress(ll, 8443, scopeId = 1)),
            ),
            "another port",
        )
    }

    /** The pool's key still names the destination; the address comparison happens before a new connection is made. */
    @Test fun poolKeysByDestinationName() {
        val origin = H3Target("server.test", "server.test", 443)
        assertEquals(origin.key, H3Target("server.test", "server.test", 443).key)
        assertNotEquals(origin.key, H3Target("server.test", "alt.server.test", 443).key)
        assertNotEquals(origin.key, H3Target("a.wild.test", "server.test", 443).key, "another origin: another TLS configuration")
    }
}
