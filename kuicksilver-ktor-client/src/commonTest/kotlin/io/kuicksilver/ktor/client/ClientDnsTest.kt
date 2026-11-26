// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.network.setSystemLookupForTest
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/**
 * The application's resolver (`KuicksilverEngineConfig.dns`) through the engine: what it is asked for over TCP, QUIC,
 * proxies and Alt-Svc, how its failures and stalls end a call, and that its answers never stand in for the host name in
 * TLS (threat model 3.25).
 */
class ClientDnsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val loopback = IpAddress.parse("127.0.0.1")

    /** A resolver that answers [map] (anything else: no address) and records every name it is asked for. */
    private class Recording(
        private val map: Map<String, List<IpAddress>>,
    ) : Dns {
        private val lock = Mutex()
        private val names = ArrayList<String>()

        override suspend fun lookup(host: String): List<IpAddress> {
            lock.withLock { names += host }
            return map[host].orEmpty()
        }

        suspend fun asked(): List<String> = lock.withLock { names.toList() }
    }

    /** Every DNS event of a client, as text, in order ([KuicksilverEventListener.dnsStart], [KuicksilverEventListener.dnsEnd]). */
    private class DnsEvents : KuicksilverEventListener() {
        val seen = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)

        override fun dnsStart(
            request: io.ktor.client.request.HttpRequestData,
            host: String,
            ipv6: Boolean?,
        ) {
            seen.trySend("start $host ${family(ipv6)} ${request.url.encodedPath}")
        }

        override fun dnsEnd(
            request: io.ktor.client.request.HttpRequestData,
            host: String,
            ipv6: Boolean?,
            addresses: List<IpAddress>,
            failure: Throwable?,
        ) {
            seen.trySend("end $host ${family(ipv6)} $addresses ${failure?.message}")
        }

        private fun family(ipv6: Boolean?) =
            if (ipv6 == null) {
                "both"
            } else if (ipv6) {
                "v6"
            } else {
                "v4"
            }

        fun drain(): List<String> = generateSequence { seen.tryReceive().getOrNull() }.toList()
    }

    /**
     * As OkHttp's `dnsStart` and `dnsEnd`: one pair per lookup the engine makes, the end with what it connects to (after the
     * destination check) or with the failure. A plain [Dns] is one lookup of both families, a [FamilyDns] and the system's
     * one per family; an address literal is no lookup.
     */
    @Test fun dnsEventsBracketEveryLookup() =
        clientTest {
            val (server, port) = testServer { routing { get("/{p}") { call.respondText("ok") } } }
            try {
                val plain = DnsEvents()
                testClient(engine = {
                    network { dns = Dns { listOf(loopback, IpAddress.parse("0.0.0.0")) } }
                    observability { eventListener = plain }
                }).use { c ->
                    c.get("https://server.test:$port/a")
                    assertEquals(listOf("start server.test both /a", "end server.test both [127.0.0.1] null"), plain.drain())
                    c.get("https://127.0.0.1:$port/b")
                    assertEquals(emptyList(), plain.drain(), "a literal is no lookup")
                }
                val failing = DnsEvents()
                testClient(engine = {
                    network { dns = Dns { throw IOException("boom") } }
                    observability { eventListener = failing }
                }).use { c ->
                    assertFailsWith<IOException> { c.get("https://server.test:$port/c") }
                    assertEquals(listOf("start server.test both /c", "end server.test both [] boom"), failing.drain())
                }
                val perFamily = DnsEvents()
                setSystemLookupForTest { name, ipv6 ->
                    if (name == "server.test" &&
                        !ipv6
                    ) {
                        listOf(
                            io.kuicksilver.ktor.network
                                .TcpAddress(byteArrayOf(127, 0, 0, 1), 0),
                        )
                    } else {
                        emptyList()
                    }
                }
                try {
                    testClient(engine = { observability { eventListener = perFamily } }).use { c ->
                        c.get("https://server.test:$port/d")
                        assertEquals(
                            setOf(
                                "start server.test v6 /d",
                                "end server.test v6 [] null",
                                "start server.test v4 /d",
                                "end server.test v4 [127.0.0.1] null",
                            ),
                            perFamily.drain().toSet(),
                        )
                    }
                } finally {
                    setSystemLookupForTest(null)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun theDefaultIsTheSystemResolver() {
        val config = KuicksilverEngineConfig()
        assertSame(Dns.System, config.network.dns)
        assertTrue(config.newRequestDns().isSystemForTest, "the default must keep the system path as it was")
        config.network.dns = Dns { emptyList() }
        assertTrue(!config.newRequestDns().isSystemForTest)
    }

    @Test fun theDnsResolvesTheOriginOverTcp() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val dns = Recording(mapOf("server.test" to listOf(loopback)))
                testClient(engine = { network { this.dns = dns } }).use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                }
                assertEquals(listOf("server.test"), dns.asked())
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun theDnsResolvesTheOriginOverHttp3() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("v=${call.request.local.version}") } } }
            try {
                val dns = Recording(mapOf("server.test" to listOf(loopback)))
                testClient(Http3Discovery.H3Only, engine = { network { this.dns = dns } }).use { c ->
                    val r = c.get("https://server.test:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("v=HTTP/3", r.bodyAsText())
                }
                assertEquals(listOf("server.test"), dns.asked())
            } finally {
                server.stop(100, 500)
            }
        }

    /** Both sides of the h3/h1 race connect to what one call of the resolver answered (RFC 8305 section 3, one resolution). */
    @Test fun theRaceAsksTheDnsOnce() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val dns = Recording(mapOf("server.test" to listOf(loopback)))
                testClient(Http3Discovery.Preferred, engine = { network { this.dns = dns } }).use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                }
                assertEquals(listOf("server.test"), dns.asked())
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun aFamilyDnsIsAskedForEachFamily() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val asked = Mutex()
                val families = HashSet<Pair<String, Boolean>>()
                val dns =
                    object : FamilyDns {
                        override suspend fun lookup(
                            host: String,
                            ipv6: Boolean,
                        ): List<IpAddress> {
                            asked.withLock { families += host to ipv6 }
                            return if (ipv6) emptyList() else listOf(loopback)
                        }
                    }
                testClient(engine = { network { this.dns = dns } }).use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                }
                assertEquals(setOf("server.test" to true, "server.test" to false), asked.withLock { families.toSet() })
            } finally {
                server.stop(100, 500)
            }
        }

    /** An address literal is its own address: the resolver is not asked (as OkHttp's `RouteSelector`). */
    @Test fun negative_aLiteralIsNeverAskedFor() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val dns = Dns { error("asked for $it") }
                testClient(engine = { network { this.dns = dns } }).use { c ->
                    assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * A resolver's answers are untrusted for the server's identity (threat model 3.25): TLS sends the host name as SNI and
     * verifies the certificate against that name, never against the address the resolver gave. The server's certificate
     * holds `server.test` and the IP address 127.0.0.1; a name it does not hold, pointed at 127.0.0.1 by the resolver,
     * fails, which it would not if the resolved address were verified.
     */
    @Test fun negative_theResolvedAddressNeverStandsInForTheName() =
        clientTest {
            val names = Mutex()
            val sni = ArrayList<String?>()
            val server =
                embeddedServer(KuicksilverServer, configure = {
                    tlsConnector(ClientFixtures.identity()) {
                        host = "127.0.0.1"
                        port = 0
                        // the same certificate for every name: whether a name is accepted is the client's check alone
                        sniSelector = { hello ->
                            names.withLock { sni += hello.serverName }
                            ServerTlsOverride(ClientFixtures.identity())
                        }
                    }
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val dns = Recording(mapOf("server.test" to listOf(loopback), "evil.test" to listOf(loopback)))
                testClient(engine = { network { this.dns = dns } }).use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                    assertEquals(listOf<String?>("server.test"), names.withLock { sni.toList() })
                    val e = assertFailsWith<Throwable> { c.get("https://evil.test:$port/") }
                    assertTrue(generateSequence(e) { it.cause }.any { it is TlsException }, "$e")
                }
                assertEquals(listOf<String?>("server.test", "evil.test"), names.withLock { sni.toList() })
            } finally {
                server.stop(100, 500)
            }
        }

    /** The same over QUIC: the Initial's SNI and the verified name are the URL's host, never the resolved address. */
    @Test fun negative_theResolvedAddressNeverStandsInForTheNameOverHttp3() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val dns = Recording(mapOf("server.test" to listOf(loopback), "evil.test" to listOf(loopback)))
                testClient(Http3Discovery.H3Only, engine = { network { this.dns = dns } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                    val e = assertFailsWith<Throwable> { c.get("https://evil.test:$port/") }
                    assertTrue(generateSequence(e) { it.cause }.any { it is TlsException }, "$e")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * An answer of 0.0.0.0 is never connected to: on Linux and macOS such a connect reaches this host's own listeners
     * (here the test server on 127.0.0.1), so a resolver, or whoever forges its answers, could aim the client at local
     * services ("0.0.0.0 day"). With nothing else in the answer the call fails as for a name without addresses.
     */
    @Test fun negative_anUnspecifiedAnswerIsNeverConnected() =
        clientTest {
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("reached") } } }
            try {
                val dns = Recording(mapOf("server.test" to listOf(IpAddress.parse("0.0.0.0"), IpAddress.parse("224.0.0.1"))))
                testClient(engine = { network { this.dns = dns } }).use { c ->
                    val e = assertFailsWith<IOException> { c.get("http://server.test:$port/") }
                    assertTrue("no address" in e.message.orEmpty(), "$e")
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The system resolver's answers get the same destination check (RFC 1122 section 3.2.1.3, RFC 9293 MUST-46): an answer of
     * 0.0.0.0 for a name would reach this host's own listener on Linux and macOS, here the test server on 127.0.0.1, over TCP
     * and over QUIC. The system lookup is the test's ([setSystemLookupForTest]); everything after it is the default path.
     */
    @Test fun negative_aSystemAnswerOfTheUnspecifiedAddressIsNeverConnected() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("reached") } } }
            setSystemLookupForTest { name, ipv6 ->
                if (name == "server.test" && !ipv6) {
                    listOf(
                        io.kuicksilver.ktor.network
                            .TcpAddress(ByteArray(4), 0),
                    )
                } else {
                    emptyList()
                }
            }
            try {
                val modes =
                    if (quicServerSupported()) {
                        listOf(
                            null,
                            Http3Discovery.H3Only,
                        )
                    } else {
                        listOf(null)
                    }
                for (mode in modes) {
                    testClient(mode, engine = { connectTimeout = 30.seconds }).use { c ->
                        val started = TimeSource.Monotonic.markNow()
                        val e = assertFailsWith<IOException>("$mode") { c.get("https://server.test:$port/") }
                        assertTrue("no address" in e.message.orEmpty() && started.elapsedNow() < 20.seconds, "$mode: $e")
                    }
                }
            } finally {
                setSystemLookupForTest(null)
                server.stop(100, 500)
            }
        }

    /**
     * An address literal in the URL that no connection may go to fails before any packet, over TCP and QUIC: `0.0.0.0`
     * reached this host's own listener (the test server on 127.0.0.1) on Linux and macOS.
     */
    @Test fun negative_anUnusableLiteralIsNeverConnected() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("reached") } } }
            try {
                val modes =
                    if (quicServerSupported()) {
                        listOf(
                            null,
                            Http3Discovery.H3Only,
                        )
                    } else {
                        listOf(null)
                    }
                for (mode in modes) {
                    testClient(mode, engine = { connectTimeout = 30.seconds }).use { c ->
                        val started = TimeSource.Monotonic.markNow()
                        val e = assertFailsWith<IOException>("$mode") { c.get("https://0.0.0.0:$port/") }
                        val said = generateSequence<Throwable>(e) { it.cause }.any { "no connection may go to" in it.message.orEmpty() }
                        assertTrue(said && started.elapsedNow() < 20.seconds, "$mode: $e")
                    }
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /** The default engine reads `010.0.0.1` as no host: getaddrinfo would read it as octal, 8.0.0.1 (ADR-0020). */
    @Test fun negative_theDefaultEngineRefusesAnAmbiguousNumericHost() =
        clientTest {
            testClient().use { c ->
                val e = assertFailsWith<IOException> { c.get("http://010.0.0.1:1/") }
                assertTrue(
                    generateSequence<Throwable>(e) { it.cause }.any { "neither a host name" in it.message.orEmpty() },
                    "$e",
                )
            }
        }

    /** A numeric host is no lookup, for a [FamilyDns] too: no DNS events. */
    @Test fun aNumericHostHasNoDnsEvents() =
        clientTest {
            val (server, port) = testServer(plain = true) { routing { get("/") { call.respondText("ok") } } }
            try {
                val events = DnsEvents()
                val dns =
                    object : FamilyDns {
                        override suspend fun lookup(
                            host: String,
                            ipv6: Boolean,
                        ): List<IpAddress> = error("asked for $host")
                    }
                testClient(engine = {
                    network { this.dns = dns }
                    observability { eventListener = events }
                    // the JDK's ProxySelector takes no URI with such a host
                    proxies { resolver = ProxyResolvers.None }
                }).use { c ->
                    assertEquals("ok", c.get("http://127.1:$port/").bodyAsText())
                }
                assertEquals(emptyList(), events.drain())
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun negative_aDnsThatThrowsFailsTheCall() =
        clientTest {
            val boom = IOException("boom")
            testClient(engine = { network { dns = Dns { throw boom } } }).use { c ->
                val e = assertFailsWith<IOException> { c.get("https://server.test:1/") }
                assertTrue(generateSequence<Throwable>(e) { it.cause }.any { it === boom }, "$e")
            }
            testClient(engine = { network { dns = Dns { emptyList() } } }).use { c ->
                val e = assertFailsWith<IOException> { c.get("https://server.test:1/") }
                assertTrue("no address" in e.message.orEmpty(), "$e")
            }
        }

    /**
     * A resolver's own timeout (a [CancellationException] while the call is active) fails the call at once as a failed
     * lookup, for a request and for a WebSocket, whose keys wait for the answered families ([RequestDns.answered]). Taken
     * for a cancellation, it ended that lookup as if its caller had gone: the WebSocket then waited for an answer that
     * never came, and failed only at the connect timeout.
     */
    @Test fun negative_aCancellationTheDnsThrowsFailsTheCall() =
        clientTest {
            testClient(engine = {
                network { dns = Dns { throw CancellationException("its own timeout") } }
                connectTimeout = 60.seconds
            }, block = { install(WebSockets) }).use { c ->
                for (call in listOf<suspend () -> Unit>({ c.get("https://server.test:1/") }, { c.webSocket("ws://server.test:1/") {} })) {
                    val started = TimeSource.Monotonic.markNow()
                    val e = assertFailsWith<IOException> { call() }
                    assertTrue(e !is ConnectTimeoutException && started.elapsedNow() < 30.seconds, "$e after ${started.elapsedNow()}")
                    assertTrue(generateSequence<Throwable>(e) { it.cause }.any { "its own timeout" in it.message.orEmpty() }, "$e")
                }
            }
        }

    /** A resolver that never answers ends at the connect timeout, cancelled ([Dns]: the lookup is part of connecting). */
    @Test fun negative_aStalledDnsEndsAtTheConnectTimeout() =
        clientTest {
            for (mode in listOf(null, Http3Discovery.H3Only)) {
                val entered = CompletableDeferred<Unit>()
                val cancelled = CompletableDeferred<Unit>()
                val dns =
                    Dns {
                        entered.complete(Unit)
                        try {
                            awaitCancellation()
                        } finally {
                            cancelled.complete(Unit)
                        }
                    }
                testClient(mode, engine = {
                    network { this.dns = dns }
                    connectTimeout = 300.milliseconds
                }).use { c ->
                    val started = TimeSource.Monotonic.markNow()
                    assertFailsWith<ConnectTimeoutException>("$mode") { c.get("https://server.test:443/") }
                    assertTrue(started.elapsedNow() < 10.seconds, "$mode: ${started.elapsedNow()}")
                    assertTrue(entered.isCompleted && cancelled.isCompleted, "$mode: the lookup was not cancelled")
                }
            }
        }

    /** A blocking resolver that never returns holds neither the call past its connect timeout nor the engine. */
    @Test fun negative_aStalledBlockingDnsEndsAtTheConnectTimeout() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val gate = CompletableDeferred<Unit>()
            try {
                val dns =
                    Dns.blocking {
                        runBlocking { gate.await() }
                        emptyList()
                    }
                testClient(engine = {
                    network { this.dns = dns }
                    connectTimeout = 300.milliseconds
                }).use { c ->
                    assertFailsWith<ConnectTimeoutException> { c.get("https://stalled.test:$port/") }
                    // the engine still serves calls that need no lookup
                    assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                }
            } finally {
                gate.complete(Unit)
                server.stop(100, 500)
            }
        }

    /** A call cancelled while its lookup runs cancels the lookup. */
    @Test fun aCancelledCallCancelsTheLookup() =
        clientTest {
            val entered = CompletableDeferred<Unit>()
            val cancelled = CompletableDeferred<Unit>()
            val dns =
                Dns {
                    entered.complete(Unit)
                    try {
                        awaitCancellation()
                    } finally {
                        cancelled.complete(Unit)
                    }
                }
            testClient(engine = { network { this.dns = dns } }).use { c ->
                coroutineScope {
                    val call = async { c.get("https://server.test:443/") }
                    entered.await()
                    call.cancel()
                    cancelled.await()
                }
            }
        }

    /** A huge answer is cut to a bounded list, and the call goes on with its first addresses. */
    @Test fun negative_aHugeAnswerIsBounded() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val many = listOf(loopback) + List(200_000) { IpAddress.of(byteArrayOf(127, 0, (it shr 8).toByte(), it.toByte())) }
                testClient(engine = { network { dns = Dns { many } } }).use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                }
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * An `Alt-Svc` alternative on another host is resolved by the resolver too (RFC 7838 section 2.1: the alternative is
     * the host the client connects to), and its certificate is still checked against the origin's name.
     */
    @Test fun anAlternativesHostIsResolvedByTheDns() =
        h3Test {
            var port = 0
            val (server, bound) =
                testServer {
                    routing {
                        get("/") {
                            call.response.headers.append("Alt-Svc", "h3=\"alt.test:$port\"; ma=60")
                            call.respondText("v=${call.request.local.version}")
                        }
                    }
                }
            port = bound
            try {
                val dns = Recording(mapOf("server.test" to listOf(loopback), "alt.test" to listOf(loopback)))
                testClient(Http3Discovery.Auto, engine = { network { this.dns = dns } }).use { c ->
                    assertEquals("v=HTTP/1.1", c.get("https://server.test:$port/").bodyAsText())
                    // the alternative is known now: this request races it (QUIC to alt.test, verified as server.test) against
                    // TCP; whichever wins, the QUIC side asked the resolver for the alternative's host
                    assertTrue(c.get("https://server.test:$port/").bodyAsText().startsWith("v=HTTP/"))
                }
                assertTrue("alt.test" in dns.asked(), "${dns.asked()}")
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * Through an HTTP proxy the resolver is asked for the proxy's name; the origin's name goes to the proxy in the CONNECT
     * (RFC 9110 section 9.3.6) and is never resolved here (as OkHttp's `RouteSelector`, and Netty's proxy handlers with
     * `NoopAddressResolverGroup`).
     */
    @Test fun aProxysNameIsResolvedAndTheOriginsIsNot() =
        clientTest {
            val (server, port) = testServer { routing { get("/") { call.respondText("through") } } }
            try {
                ClientProxyTest().tunnelProxy(port) { proxyPort, head ->
                    val dns = Recording(mapOf("proxy.test" to listOf(loopback)))
                    testClient(engine = {
                        network { this.dns = dns }
                        proxies { resolver = ProxyResolver { ResolvedProxy.http("proxy.test", proxyPort) } }
                    }).use { c ->
                        assertEquals("through", c.get("https://server.test:$port/").bodyAsText())
                    }
                    assertEquals(listOf("proxy.test"), dns.asked())
                    assertEquals("CONNECT server.test:$port HTTP/1.1", head().first())
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
