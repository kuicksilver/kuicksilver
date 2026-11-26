// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.Url
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.LineEnding
import io.ktor.utils.io.copyAndClose
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeByteArray
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.dns.HttpsEndpoint
import io.kuicksilver.ktor.client.dns.SvcbRecord
import io.kuicksilver.ktor.client.h3.resendsAfterEarlyEchRejection
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.ktor.network.bindTcp
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.EchConfigList
import io.kuicksilver.tls.EchKey
import io.kuicksilver.tls.EchServerKeys
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsVersions
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import io.kuicksilver.ktor.server.Kuicksilver as KuicksilverServer

/**
 * Encrypted Client Hello in the client engine (RFC 9849, RFC 9848): the configuration of a host or of an HTTPS record's
 * endpoint is offered over TCP and QUIC, a rejection is retried once with the server's retry configurations (or without ECH
 * when it sent none), GREASE goes out otherwise, and an SVCB-reliant request never falls back to a connection without the
 * records. The server is the Kuicksilver engine with [EchTestKeys] (public_name `ech.wild.test`, which the test certificate
 * covers); its `sniSelector` records the server name of every ClientHello it handled: the inner name when it decrypted ECH,
 * the public_name when it did not.
 */
@OptIn(ExperimentalAtomicApi::class)
class ClientEchTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun listOf(pem: String): EchConfigList {
        val body = pem.substringAfter("-----BEGIN ECHCONFIG-----").substringBefore("-----END ECHCONFIG-----")
        return EchConfigList.parseBase64(body.lines().joinToString(""))
    }

    private val listA by lazy { listOf(EchTestKeys.A) }
    private val keyA get() = EchKey(EchTestKeys.A)
    private val keyB get() = EchKey(EchTestKeys.B)

    private val loopback: suspend (String, Int) -> List<TcpAddress> = { _, p -> listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), p)) }

    /** The server names the server's ClientHellos carried, in order. */
    private class Names {
        private val lock = Mutex()
        private val seen = ArrayList<String?>()

        suspend fun add(name: String?) = lock.withLock { seen += name }

        suspend fun all(): List<String?> = lock.withLock { seen.toList() }
    }

    /** A Kuicksilver server (TLS and HTTP/3 on one port) with [keys], answering "ok" and counting the requests in [hits]. */
    private suspend fun echServer(
        keys: EchServerKeys?,
        names: Names,
        hits: AtomicInt = AtomicInt(0),
        onHello: suspend (String?) -> Unit = {},
        earlyData: Boolean = false,
    ): Pair<TestServer, Int> {
        val server =
            embeddedServer(KuicksilverServer, configure = {
                http3 { earlyData { enabled = earlyData } }
                tlsConnector {
                    tls { identity = ClientFixtures.identity() }
                    host = "127.0.0.1"
                    port = 0
                    tls { echKeys = keys }
                    tls {
                        sniSelector = { hello ->
                            names.add(hello.serverName)
                            onHello(hello.serverName)
                            // the one certificate covers the inner name and the public_name (RFC 9849 section 6.1.7)
                            io.kuicksilver.tls.ServerTlsOverride(ClientFixtures.identity())
                        }
                    }
                }
            }) {
                routing {
                    get("/") {
                        hits.incrementAndFetch()
                        call.respondText("ok")
                    }
                }
            }
        server.startSuspend(false)
        return server to
            server.engine
                .resolvedConnectors()
                .first()
                .port
    }

    private fun client(
        discovery: Http3Discovery? = null,
        more: KuicksilverEngineConfig.() -> Unit = {},
    ) = testClient(discovery, engine = {
        resolverForTest = loopback
        connectTimeout = 20.seconds
        more()
    })

    @Test fun hostConfigurationIsOfferedAndAcceptedOverTcp() =
        clientTest {
            val names = Names()
            val (server, port) = echServer(EchServerKeys(listOf(keyA)), names)
            try {
                helloRelay(port) { relayPort, hellos ->
                    client(more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).use { c ->
                        assertEquals("ok", c.get("https://server.test:$relayPort/").bodyAsText())
                    }
                    val hello = ClientHelloView.parse(withTimeout(10.seconds) { hellos.receive() })
                    // RFC 9849 section 6.1, outer rule 5: the outer SNI is the public_name; the real name is encrypted
                    assertEquals(EchTestKeys.PUBLIC_NAME, hello.serverName)
                    assertTrue(ECH_EXTENSION in hello.extensions)
                }
                assertEquals(listOf<String?>("server.test"), names.all(), "the server decrypted the inner ClientHello")
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * A configLists key is a host name, compared as host names compare: case and a trailing dot do not keep the configuration
     * from being offered (a mismatch would have sent GREASE with the name in the clear); two keys for one host are refused.
     */
    @Test fun configListKeysAreComparedAsHostNames() =
        clientTest {
            val names = Names()
            val (server, port) = echServer(EchServerKeys(listOf(keyA)), names)
            try {
                helloRelay(port) { relayPort, hellos ->
                    client(more = { tls { ech { configLists = mapOf("Server.TEST." to listA) } } }).use { c ->
                        assertEquals("ok", c.get("https://server.test:$relayPort/").bodyAsText())
                    }
                    val hello = ClientHelloView.parse(withTimeout(10.seconds) { hellos.receive() })
                    assertEquals(EchTestKeys.PUBLIC_NAME, hello.serverName)
                }
                assertEquals(listOf<String?>("server.test"), names.all(), "the server decrypted the inner ClientHello")
            } finally {
                server.stopSuspend(0, 0)
            }
            val e =
                assertFailsWith<IllegalArgumentException> {
                    client(more = { tls { ech { configLists = mapOf("server.test" to listA, "SERVER.test." to listA) } } }).close()
                }
            assertTrue("server.test" in e.message!!, e.message)
        }

    /** RFC 9849 section 6.2.1: GREASE ECH on every connection without a configuration, by default; off when switched off. */
    @Test fun greaseByDefault() =
        clientTest {
            val names = Names()
            val (server, port) = echServer(null, names)
            try {
                helloRelay(port) { relayPort, hellos ->
                    client().use { c -> assertEquals("ok", c.get("https://server.test:$relayPort/").bodyAsText()) }
                    val greased = ClientHelloView.parse(withTimeout(10.seconds) { hellos.receive() })
                    assertEquals("server.test", greased.serverName)
                    assertTrue(ECH_EXTENSION in greased.extensions, "GREASE encrypted_client_hello")
                    client(more = { tls { ech { grease = false } } }).use { c ->
                        assertEquals("ok", c.get("https://server.test:$relayPort/").bodyAsText())
                    }
                    val plain = ClientHelloView.parse(withTimeout(10.seconds) { hellos.receive() })
                    assertFalse(ECH_EXTENSION in plain.extensions)
                }
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * RFC 9849 section 6.1.6: the server rejects (another key), the client authenticates the public_name, aborts, and retries
     * once on a new connection with the retry configurations, which the server decrypts.
     */
    @Test fun rejectionIsRetriedOnceWithTheRetryConfigurationsOverTcp() =
        clientTest {
            val names = Names()
            val hits = AtomicInt(0)
            val (server, port) = echServer(EchServerKeys(listOf(keyB)), names, hits)
            try {
                client(more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                }
                assertEquals(listOf<String?>(EchTestKeys.PUBLIC_NAME, "server.test"), names.all())
                assertEquals(1, hits.load(), "the rejected connection carried no request")
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * Per-host pins and ECH (M2 of the DX review): the rejected connection is authenticated for the public_name by the base
     * trust alone (RFC 9849 section 6.1.7), so neither the origin's pins nor the public_name's apply to it; the retry is held
     * to the origin's pins. Pinned wrong, the retry fails with the origin's PinMismatch after the rejection's handshake.
     */
    @Test fun negative_theEchRetryIsHeldToTheOriginsPins() =
        clientTest {
            val leaf = io.kuicksilver.tls.SpkiSha256(TestCerts.serverSpkiSha256)
            val wrong = io.kuicksilver.tls.SpkiSha256(ByteArray(32) { 7 })
            for (originPinned in listOf(true, false)) {
                val names = Names()
                val (server, port) = echServer(EchServerKeys(listOf(keyB)), names)
                try {
                    client(more = {
                        tls {
                            ech { configLists = mapOf("server.test" to listA) }
                            pins {
                                add("server.test", if (originPinned) leaf else wrong)
                                add(EchTestKeys.PUBLIC_NAME, wrong) // never consulted: the rejection is not the origin
                            }
                        }
                    }).use { c ->
                        if (originPinned) {
                            assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                        } else {
                            val e = assertFailsWith<Throwable> { c.get("https://server.test:$port/") }
                            val v = generateSequence(e) { it.cause }.filterIsInstance<io.kuicksilver.tls.TlsException.Verify>().first()
                            assertEquals("server.test", (v.reason as io.kuicksilver.tls.VerifyReason.PinMismatch).host, "$e")
                        }
                    }
                    assertEquals(listOf<String?>(EchTestKeys.PUBLIC_NAME, "server.test"), names.all().take(2), "rejected, then retried")
                } finally {
                    server.stopSuspend(0, 0)
                }
            }
        }

    /** RFC 9849 section 6.1.6: a server without ECH sends no retry configurations: "securely disabled", retried without ECH. */
    @Test fun negative_serverWithoutEchIsRetriedWithoutEch() =
        clientTest {
            val names = Names()
            val (server, port) = echServer(null, names)
            try {
                client(more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).use { c ->
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                }
                assertEquals(listOf<String?>(EchTestKeys.PUBLIC_NAME, "server.test"), names.all())
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * RFC 9849 section 6.1.6: "Clients SHOULD NOT accept "retry_config" in response to a connection initiated in response to
     * a "retry_config"": the server rotates its keys between the two connections, so the retry is rejected as well, and the
     * request fails with the rejection instead of a third connection ("If a client does not retry, it MUST report an error").
     */
    @Test fun negative_aRejectedRetryIsNotRetriedAgain() =
        clientTest {
            val names = Names()
            val keys = EchServerKeys(listOf(keyB))
            val rotated = AtomicInt(0)
            val (server, port) =
                echServer(keys, names, onHello = { if (rotated.incrementAndFetch() == 1) keys.rotate(listOf(keyA)) })
            try {
                client(more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).use { c ->
                    val e = assertFailsWith<Throwable> { c.get("https://server.test:$port/") }
                    assertNotNull(echRejectionIn(e), "$e")
                }
                assertEquals(listOf<String?>(EchTestKeys.PUBLIC_NAME, EchTestKeys.PUBLIC_NAME), names.all())
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * RFC 9849 section 6.1, rule 1: ECH is TLS 1.3 only. Under the default `versions = Tls12And13` (and when it is set
     * explicitly) a host configuration is taken, and the connections that offer it are TLS 1.3 only, to the origin and to a
     * proxy alike; the others keep TLS 1.2 (until 0.3.0 such a configuration was refused with TLS 1.2 allowed).
     */
    @Test fun negative_hostConfigurationMakesItsConnectionsTls13Only() {
        for (explicit in kotlin.collections.listOf(false, true)) {
            val config =
                KuicksilverEngineConfig().apply {
                    tls {
                        if (explicit) versions = TlsVersions.Tls12And13
                        ech { configLists = mapOf("server.test" to listA) }
                    }
                    proxies { tls { ech { configLists = mapOf("proxy.test" to listA) } } }
                }
            assertEquals(TlsVersions.Tls12And13, config.tls.versions)
            val offered =
                config.tlsConfigFor(
                    "server.test",
                    kotlin.collections.listOf("h2", "http/1.1"),
                    quic = false,
                    ech = EchRoute(listA).offer,
                )
            assertEquals(listA, offered.echConfigList)
            assertEquals(TlsVersions.Tls13, offered.versions, "an ECH offer never allows TLS 1.2")
            // securely disabled (no offer left), and another host: TLS 1.2 allowed again
            val plain =
                config.tlsConfigFor(
                    "other.test",
                    kotlin.collections.listOf("h2", "http/1.1"),
                    quic = false,
                    ech = EchRoute(null).offer,
                )
            assertNull(plain.echConfigList)
            assertEquals(TlsVersions.Tls12And13, plain.versions)
            // the retry of a rejection is part of the ECH route: TLS 1.3 only, with the retry configurations and without any
            // (securely disabled) alike
            val route = EchRoute(listA)
            val disabled = assertNotNull(route.rejected(route.offer, TlsException.EchRejected(null)))
            assertNull(disabled.list)
            val retry = config.tlsConfigFor("server.test", kotlin.collections.listOf("h2", "http/1.1"), quic = false, ech = disabled)
            assertNull(retry.echConfigList)
            assertEquals(TlsVersions.Tls13, retry.versions, "the secure-disable retry stays TLS 1.3 only")
            val proxy = config.proxyTlsConfigFor("proxy.test")
            assertEquals(listA, proxy.echConfigList)
            assertEquals(TlsVersions.Tls13, proxy.versions, "the proxy's own ECH offer never allows TLS 1.2")
            assertEquals(TlsVersions.Tls12And13, config.proxyTlsConfigFor("other-proxy.test").versions)
        }
        client(more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).close()
    }

    /**
     * Self-attack, RFC 9849 section 6.1: a server of an ECH host that speaks TLS 1.2 at most (here one that answers every
     * ClientHello with `protocol_version`, as such a server answers a TLS 1.3-only one). The request fails with that alert,
     * and every ClientHello that went out carried ECH (the real name never in the clear) and offered TLS 1.3 alone: no fallback
     * to TLS 1.2 or to a connection without ECH. The default client's own ClientHello offers TLS 1.3 and 1.2, nothing older.
     */
    @Test fun negative_echHostWithATls12OnlyServerFailsWithoutFallback() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val listener = bindTcp(selector, "127.0.0.1", 0)
            val hellos = Channel<ByteArray>(Channel.UNLIMITED)
            try {
                coroutineScope {
                    val stub =
                        launch {
                            while (true) {
                                val s = listener.accept()
                                launch {
                                    s.use {
                                        runCatching {
                                            hellos.send(readRecord(s.openReadChannel()))
                                            val out = s.openWriteChannel(autoFlush = true)
                                            out.writeByteArray(byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46))
                                            out.flush()
                                        }
                                    }
                                }
                            }
                        }
                    val port = (listener.localAddress as InetSocketAddress).port
                    client(more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).use { c ->
                        val e = assertFailsWith<Throwable> { c.get("https://server.test:$port/") }
                        val alert = generateSequence(e) { it.cause }.filterIsInstance<TlsException.AlertReceived>().firstOrNull()
                        assertEquals(70, alert?.code, "protocol_version in $e")
                    }
                    var count = 0
                    while (true) {
                        val hello = hellos.tryReceive().getOrNull() ?: break
                        count++
                        val view = ClientHelloView.parse(hello)
                        assertEquals(EchTestKeys.PUBLIC_NAME, view.serverName, "the real name never in the clear")
                        assertTrue(ECH_EXTENSION in view.extensions)
                        assertEquals(kotlin.collections.listOf(0x0304), view.supportedVersions, "TLS 1.3 alone with ECH")
                    }
                    assertTrue(count >= 1)
                    client().use { c -> assertFailsWith<Throwable> { c.get("https://server.test:$port/") } }
                    val plain = ClientHelloView.parse(withTimeout(10.seconds) { hellos.receive() })
                    assertEquals("server.test", plain.serverName)
                    assertEquals(kotlin.collections.listOf(0x0304, 0x0303), plain.supportedVersions, "the default: 1.3, then 1.2")
                    stub.cancel()
                }
            } finally {
                listener.close()
                selector.close()
            }
        }

    /**
     * A host configuration without a usable ECHConfig is refused when the engine is created: it would otherwise send the
     * host's name in the clear (GREASE) on every connection. The message says what is wrong with the list.
     */
    @Test fun negative_hostConfigurationWithoutUsableConfigIsRefused() {
        val other = byteArrayOf(0xfe.toByte(), 0x0c, 0, 3, 1, 2, 3)
        val unusable = EchConfigList.parse(byteArrayOf(0, other.size.toByte()) + other)
        val e =
            assertFailsWith<IllegalArgumentException> {
                client(more = { tls { ech { configLists = mapOf("server.test" to unusable) } } }).close()
            }
        assertTrue("server.test" in e.message!! && "no ECHConfig" in e.message!!, e.message)
        client(more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).close()
    }

    /**
     * Through an HTTP CONNECT proxy the TLS session inside the tunnel is the origin's, with the origin's ECH: the proxy hop
     * is plain TCP and carries no ClientHello of its own (it learns the origin's name from the CONNECT line anyway).
     */
    @Test fun echGoesInsideAConnectTunnel() =
        clientTest {
            val names = Names()
            val (server, port) = echServer(EchServerKeys(listOf(keyA)), names)
            try {
                capturingTunnel(port) { proxyPort, connectLine, hello ->
                    testClient(engine = {
                        proxy = ProxyBuilder.http(Url("http://127.0.0.1:$proxyPort"))
                        tls { ech { configLists = mapOf("server.test" to listA) } }
                    }).use { c -> assertEquals("ok", c.get("https://server.test:$port/").bodyAsText()) }
                    assertEquals("CONNECT server.test:$port HTTP/1.1", connectLine())
                    val h = ClientHelloView.parse(withTimeout(10.seconds) { hello.receive() })
                    assertEquals(EchTestKeys.PUBLIC_NAME, h.serverName)
                    assertTrue(ECH_EXTENSION in h.extensions)
                }
                assertEquals(listOf<String?>("server.test"), names.all(), "the server decrypted the inner ClientHello")
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun acceptedOverHttp3() =
        h3Test {
            val names = Names()
            val (server, port) = echServer(EchServerKeys(listOf(keyA)), names)
            try {
                client(Http3Discovery.H3Only, more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).use { c ->
                    val r = c.get("https://server.test:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                }
                assertEquals(listOf<String?>("server.test"), names.all())
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    @Test fun rejectionIsRetriedOnceOverHttp3() =
        h3Test {
            val names = Names()
            val hits = AtomicInt(0)
            val (server, port) = echServer(EchServerKeys(listOf(keyB)), names, hits)
            try {
                client(Http3Discovery.H3Only, more = { tls { ech { configLists = mapOf("server.test" to listA) } } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                }
                assertEquals(listOf<String?>(EchTestKeys.PUBLIC_NAME, "server.test"), names.all())
                assertEquals(1, hits.load())
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * 0-RTT under ECH: the early data goes under the inner ClientHello's PSK (RFC 9849 section 6.1, outer rule 7 copies
     * `early_data` to the outer ClientHello). When the server then rejects ECH it handshakes on the outer ClientHello,
     * whose PSK is GREASE, and ignores the early data (RFC 8446 section 4.2.10): the request was not processed, and goes
     * once more on the retry connection with the retry configurations. Exactly one request reaches the application.
     */
    @Test fun earlyDataUnderARejectedEchIsSentAgainOnTheRetry() =
        h3Test {
            val names = Names()
            val hits = AtomicInt(0)
            val keys = EchServerKeys(listOf(keyA))
            // the server answers the rejected 0-RTT connection's ClientHello only once the client handed that connection to the
            // request (H3Pool.afterAcquireForTest): the rejection then reaches the request, not the connection's setup (whose
            // own retry would hide this path). The server issues tickets that allow 0-RTT, or there would be no early data.
            val requestHasConnection = CompletableDeferred<Unit>()
            val gateArmed = AtomicInt(0)
            val retries = kotlin.concurrent.atomics.AtomicReference(emptyList<Int>())
            val listener =
                object : KuicksilverEventListener() {
                    override fun retry(
                        request: io.ktor.client.request.HttpRequestData,
                        attempt: Int,
                        cause: Throwable,
                    ) {
                        while (true) {
                            val now = retries.load()
                            if (retries.compareAndSet(now, now + attempt)) break
                        }
                    }
                }
            val (server, port) =
                echServer(keys, names, hits, earlyData = true, onHello = { name ->
                    if (name == EchTestKeys.PUBLIC_NAME && gateArmed.compareAndSet(1, 0)) {
                        withTimeout(10.seconds) { requestHasConnection.await() }
                    }
                })
            try {
                client(Http3Discovery.H3Only, more = {
                    http3 { earlyData { enabled = true } }
                    tls { ech { configLists = mapOf("server.test" to listA) } }
                    observability { eventListener = listener }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                    // the ticket arrives after the handshake: wait for it, then forget the connection, so the next request
                    // resumes in 0-RTT (dropping it before the ticket came would leave nothing to resume with)
                    withTimeout(30.seconds) { while (engine.h3.ticketsForTest() == 0) yield() }
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    keys.rotate(listOf(keyB))
                    gateArmed.store(1)
                    engine.h3.afterAcquireForTest = { requestHasConnection.complete(Unit) }
                    val earlyRetries = engine.h3.echEarlyRetriesForTest.load()
                    retries.store(emptyList())
                    val r = c.get("https://server.test:$port/")
                    assertEquals("ok", r.bodyAsText())
                    assertTrue(requestHasConnection.isCompleted)
                    assertEquals(earlyRetries + 1, engine.h3.echEarlyRetriesForTest.load(), "the early request went again on the retry")
                    // a repeat on a new connection, as for a request the server did not process: the retry event and the
                    // diagnostics count it alike
                    assertEquals(listOf(2), retries.load(), "the retry event's attempt number")
                    assertEquals(2, r.kuicksilverDiagnostics?.attempts, "${r.kuicksilverDiagnostics}")
                }
                assertEquals(listOf<String?>("server.test", EchTestKeys.PUBLIC_NAME, "server.test"), names.all())
                assertEquals(2, hits.load(), "the early request was processed once, on the retry")
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    private fun record(
        owner: String,
        target: String,
        vararg alpn: String,
        ech: ByteArray?,
        noDefaultAlpn: Boolean = false,
    ) = SvcbRecord(1, target, alpn.toList(), noDefaultAlpn, null, emptyList(), emptyList(), 300, owner, ech)

    /** RFC 9848 section 3: an HTTPS record's `ech` is offered on the connection to its endpoint (HTTP/3 only: no-default-alpn). */
    @Test fun httpsRecordEchIsOffered() =
        h3Test {
            val names = Names()
            val (server, port) = echServer(EchServerKeys(listOf(keyA)), names)
            try {
                val name = "_$port._https.server.test"
                val source =
                    HttpsRecordsForTest { n ->
                        if (n ==
                            name
                        ) {
                            listOf(record(name, "server.test", "h3", ech = listA.bytes, noDefaultAlpn = true))
                        } else {
                            emptyList()
                        }
                    }
                client(Http3Discovery.Auto, more = { network { httpsRecords = source } }).use { c ->
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get("https://server.test:$port/").version)
                }
                assertEquals(listOf<String?>("server.test"), names.all())
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * RFC 9848 section 5.1: every endpoint has `ech`, so the client is SVCB-reliant: when the endpoint cannot be reached the
     * request fails, and the origin (which answers over TCP without ECH) is never tried. The same records without `ech` let
     * the request fall back to the origin, as an SVCB-optional client does (RFC 9460 section 3).
     */
    @Test fun negative_echReliantRequestNeverFallsBackToTheOrigin() =
        clientTest {
            val names = Names()
            val (server, port) = echServer(null, names)
            try {
                val name = "_$port._https.server.test"
                // the endpoint's name resolves to nothing: no connection can be set up there
                val resolver: suspend (String, Int) -> List<TcpAddress> = { h, p -> if (h == "gone.test") emptyList() else loopback(h, p) }
                for (ech in listOf(listA.bytes, null)) {
                    val source =
                        HttpsRecordsForTest { n ->
                            if (n ==
                                name
                            ) {
                                listOf(record(name, "gone.test", "http/1.1", ech = ech))
                            } else {
                                emptyList()
                            }
                        }
                    testClient(Http3Discovery.Auto, engine = {
                        resolverForTest = resolver
                        connectTimeout = 20.seconds
                        network { httpsRecords = source }
                    }).use { c ->
                        if (ech != null) {
                            assertFailsWith<Throwable> { c.get("https://server.test:$port/") }
                        } else {
                            assertEquals("ok", c.get("https://server.test:$port/").bodyAsText())
                        }
                    }
                }
                assertEquals(listOf<String?>("server.test"), names.all(), "only the SVCB-optional request reached the origin")
            } finally {
                server.stopSuspend(0, 0)
            }
        }

    /**
     * Routes of HTTPS record endpoints: the QUIC and TCP sides of one record share one (one retry for both), but two records
     * for the same host and port with different `ech` values each offer their own configuration.
     */
    @Test fun echRoutesAreKeyedByTheRecordsEchValue() {
        val listB = listOf(EchTestKeys.B)
        val routes = EchRoutesOfEndpoints()
        val quicA = HttpsEndpoint("svc.test", 443, quic = true, tcp = false, ech = listA.bytes)
        val tcpA = HttpsEndpoint("svc.test", 443, quic = false, tcp = true, ech = listA.bytes.copyOf())
        val tcpB = HttpsEndpoint("svc.test", 443, quic = false, tcp = true, ech = listB.bytes)
        val a = assertNotNull(routes.of(quicA))
        assertTrue(a === routes.of(tcpA), "one record's sides share a route")
        val b = assertNotNull(routes.of(tcpB))
        assertTrue(a !== b, "another ech value for the same target: another route")
        assertEquals(listA, a.offer.list)
        assertEquals(listB, b.offer.list)
        assertNull(routes.of(HttpsEndpoint("svc.test", 443, quic = true, tcp = true)))
        assertNull(routes.of(null))
    }

    @Test fun echRouteRetriesOnceAndSharesTheRetryBetweenSiblings() {
        val route = EchRoute(listA)
        val first = route.offer
        assertEquals(listA, first.list)
        assertFalse(first.retry)
        val retryConfigs = listOf(EchTestKeys.B)
        val retry = assertNotNull(route.rejected(first, TlsException.EchRejected(retryConfigs)))
        assertEquals(retryConfigs, retry.list)
        assertTrue(retry.retry)
        // the other side of a race, rejected with the first offer as well: it takes the retry already set, no new one
        val sibling = assertNotNull(route.rejected(first, TlsException.EchRejected(null)))
        assertEquals(retryConfigs, sibling.list)
        // a rejected retry is not retried (RFC 9849 section 6.1.6)
        assertNull(route.rejected(retry, TlsException.EchRejected(retryConfigs)))
        // securely disabled: no usable retry configurations, the retry offers none
        val disabled = assertNotNull(EchRoute(listA).let { it.rejected(it.offer, TlsException.EchRejected(null)) })
        assertNull(disabled.list)
    }

    /**
     * The hop to an `https://` proxy has its own ClientHello: it never offers the origins' configurations of the `tls` block,
     * not even one for the proxy's own name, and it sends GREASE as [EchClientConfig.grease] says.
     */
    @Test fun negative_proxyHopOffersNoEchConfiguration() {
        for (g in kotlin.collections.listOf(true, false)) {
            val config =
                KuicksilverEngineConfig().apply {
                    tls {
                        versions = TlsVersions.Tls13
                        ech {
                            configLists = mapOf("proxy.internal" to listA)
                            grease = g
                        }
                    }
                }
            val built = config.proxyTlsConfigFor("proxy.internal")
            assertNull(built.echConfigList, "the tls block's ECH configuration went to the proxy")
            assertEquals(g, built.echGrease, "GREASE on the proxy hop follows ech.grease")
        }
    }

    /** A rejection on the proxy hop is the proxy's: it never makes the origin's connection retry with its configurations. */
    @Test fun negative_aProxyHopRejectionIsNotTheOrigins() {
        val proxy = ProxyTlsException("TLS to the proxy failed", TlsException.EchRejected(listOf(EchTestKeys.B)))
        assertNull(echRejectionIn(proxy))
        assertNull(echRejectionIn(RuntimeException("wrapped", proxy)))
        assertNotNull(echRejectionIn(RuntimeException("wrapped", TlsException.EchRejected(null))))
    }

    /**
     * A 0-RTT request on a connection whose ECH was rejected is sent once more, on a connection with the retry's offer; never
     * when that connection already was the retry (RFC 9849 section 6.1.6: one retry), which would make a third connection.
     */
    @Test fun negative_anEarlyRequestOnARejectedRetryIsNotSentAThirdTime() {
        assertTrue(resendsAfterEarlyEchRejection(alreadyResent = false, handshakeComplete = false, offeredRetry = false))
        assertFalse(resendsAfterEarlyEchRejection(alreadyResent = false, handshakeComplete = false, offeredRetry = true))
        assertFalse(resendsAfterEarlyEchRejection(alreadyResent = true, handshakeComplete = false, offeredRetry = false))
        assertFalse(resendsAfterEarlyEchRejection(alreadyResent = false, handshakeComplete = true, offeredRetry = false))
    }

    // ---- wire helpers ----

    /** A ClientHello's server_name (host_name) and extension types, read from its first TLS record. */
    private class ClientHelloView(
        val serverName: String?,
        val extensions: List<Int>,
        /** The versions of `supported_versions` (RFC 9846 section 4.3.1) in order, GREASE values left out; empty without it. */
        val supportedVersions: List<Int>,
    ) {
        companion object {
            fun parse(record: ByteArray): ClientHelloView {
                var p = 5 + 4 + 2 + 32 // record header, handshake header, legacy_version, random

                fun u8() = record[p++].toInt() and 0xff

                fun u16() = (u8() shl 8) or u8()
                // each length read first: `p += u8()` would add to the p before the read
                val sessionId = u8()
                p += sessionId
                val suites = u16()
                p += suites
                val compression = u8()
                p += compression
                val extensions = u16()
                val end = p + extensions
                val types = ArrayList<Int>()
                val versions = ArrayList<Int>()
                var sni: String? = null
                while (p + 4 <= end) {
                    val type = u16()
                    val len = u16()
                    if (type == 0) {
                        // server_name_list length (2), name_type (1), HostName length (2)
                        val n = ((record[p + 3].toInt() and 0xff) shl 8) or (record[p + 4].toInt() and 0xff)
                        sni = record.copyOfRange(p + 5, p + 5 + n).decodeToString()
                    }
                    if (type == 0x2b) {
                        for (i in 0 until (record[p].toInt() and 0xff) / 2) {
                            val v = ((record[p + 1 + 2 * i].toInt() and 0xff) shl 8) or (record[p + 2 + 2 * i].toInt() and 0xff)
                            if (v and 0x0f0f != 0x0a0a) versions += v
                        }
                    }
                    types += type
                    p += len
                }
                return ClientHelloView(sni, types, versions)
            }
        }
    }

    /**
     * A TCP relay on 127.0.0.1 to [originPort] that hands the first TLS record of every connection (the ClientHello) to
     * [block]'s channel before forwarding it.
     */
    private suspend fun helloRelay(
        originPort: Int,
        block: suspend (Int, Channel<ByteArray>) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        val hellos = Channel<ByteArray>(Channel.UNLIMITED)
        try {
            coroutineScope {
                val relay =
                    launch {
                        while (true) {
                            val s = listener.accept()
                            launch {
                                s.use {
                                    val input = s.openReadChannel()
                                    val output = s.openWriteChannel(autoFlush = true)
                                    connectTcp(selector, InetSocketAddress("127.0.0.1", originPort)).use { o ->
                                        val oIn = o.openReadChannel()
                                        val oOut = o.openWriteChannel(autoFlush = true)
                                        val first = readRecord(input)
                                        hellos.send(first)
                                        oOut.writeByteArray(first)
                                        coroutineScope {
                                            launch { runCatching { input.copyAndClose(oOut) } }
                                            runCatching { oIn.copyAndClose(output) }
                                        }
                                    }
                                }
                            }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port, hellos)
                relay.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    /** An HTTP CONNECT proxy to 127.0.0.1:[originPort] that reports the CONNECT line and the first TLS record in the tunnel. */
    private suspend fun capturingTunnel(
        originPort: Int,
        block: suspend (Int, () -> String?, Channel<ByteArray>) -> Unit,
    ) {
        val selector = SelectorManager(Dispatchers.IO)
        val listener = bindTcp(selector, "127.0.0.1", 0)
        val hello = Channel<ByteArray>(Channel.UNLIMITED)
        var line: String? = null
        try {
            coroutineScope {
                val proxy =
                    launch {
                        listener.accept().use { s ->
                            val input = s.openReadChannel()
                            val output = s.openWriteChannel(autoFlush = true)
                            line = input.readLine(LineEnding.Lenient)
                            while (input.readLine(LineEnding.Lenient)?.isNotEmpty() == true) {}
                            connectTcp(selector, InetSocketAddress("127.0.0.1", originPort)).use { o ->
                                output.writeStringUtf8("HTTP/1.1 200 Connection established\r\n\r\n")
                                val oIn = o.openReadChannel()
                                val oOut = o.openWriteChannel(autoFlush = true)
                                val first = readRecord(input)
                                hello.send(first)
                                oOut.writeByteArray(first)
                                coroutineScope {
                                    launch { runCatching { input.copyAndClose(oOut) } }
                                    runCatching { oIn.copyAndClose(output) }
                                }
                            }
                        }
                    }
                block((listener.localAddress as InetSocketAddress).port, { line }, hello)
                proxy.cancel()
            }
        } finally {
            listener.close()
            selector.close()
        }
    }

    private suspend fun readRecord(input: ByteReadChannel): ByteArray {
        val head = input.readByteArray(5)
        val len = ((head[3].toInt() and 0xff) shl 8) or (head[4].toInt() and 0xff)
        return head + input.readByteArray(len)
    }

    private companion object {
        /** encrypted_client_hello (RFC 9849 section 11.1). */
        const val ECH_EXTENSION = 0xfe0d
    }
}
