// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.client.Http3Discovery
import io.kuicksilver.ktor.network.ipv6Bindable
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.datagramIoSplitForTest
import io.kuicksilver.quic.datagramIoSplitSupportedForTest
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlin.concurrent.atomics.update
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import io.kuicksilver.ktor.client.Kuicksilver as KuicksilverClient

/**
 * A server connector without a host binds every interface of both families since 0.3.0 (ADR-0026): one dual-stack socket
 * per protocol on `::`, which IPv4 clients reach as IPv4-mapped addresses. Our client reaches it on `127.0.0.1` and `::1`,
 * over TCP (HTTP/2 and HTTP/1.1) and over UDP (HTTP/3).
 *
 * A wildcard bind may share its port number with another process's loopback socket on macOS (tools/check/wildcard-binds.py):
 * each answer carries a token of this server, and a start whose port answers with another's token, or not at all, is
 * retried on another port.
 */
class ServerEveryInterfaceTest {
    private suspend fun startEverywhere(
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit,
        check: suspend (port: Int, token: String) -> Unit,
    ) {
        var last: Throwable? = null
        repeat(ATTEMPTS) {
            val token = Random.nextLong().toString(16)
            val server =
                embeddedServer(Kuicksilver, configure = {
                    configure()
                    shutdownGracePeriod = 0
                }) {
                    routing {
                        get("/") { call.respondText("$token ${call.request.local.version}") }
                        get("/addresses") {
                            val l = call.request.local
                            call.respondText("$token ${l.remoteHost} ${l.remoteAddress} ${l.localHost} ${l.localAddress}")
                        }
                    }
                }
            server.startSuspend(false)
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                check(port, token)
                return
            } catch (e: TokenMismatch) {
                last = e
            } finally {
                server.stopSuspend(0, 500)
            }
        }
        throw AssertionError("no port of our own after $ATTEMPTS attempts", last)
    }

    private fun client(discovery: Http3Discovery?) =
        HttpClient(KuicksilverClient) {
            engine {
                tls { trust = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa))) }
                http3 { discovery?.let { this.discovery = it } ?: run { enabled = false } }
            }
        }

    /** Whether this host has an IPv6 loopback to bind (a datagram socket on `::1`, closed at once). */
    private suspend fun ipv6Loopback(): Boolean = runCatching { DatagramIo.open(InetSocketAddress("::1", 0)).close() }.isSuccess

    private class TokenMismatch(
        message: String,
    ) : Exception(message)

    private fun body(
        text: String,
        token: String,
    ): String {
        val (got, version) = text.split(' ', limit = 2)
        if (got != token) throw TokenMismatch("another server answered: $text")
        return version
    }

    @Test fun tlsConnectorWithoutHostServesIpv4AndIpv6() =
        h3ServerTest {
            startEverywhere({
                tlsConnector /* wildcard on purpose: the default bind is the subject */ {
                    tls { identity = ServerFixtures.identity() }
                    port = 0
                }
            }) { port, token ->
                val hosts = if (ipv6Bindable() && ipv6Loopback()) listOf("127.0.0.1", "[::1]") else listOf("127.0.0.1")
                for (host in hosts) {
                    client(null).use { c ->
                        val r = c.get("https://$host:$port/")
                        assertEquals("HTTP/2", body(r.bodyAsText(), token), host)
                        assertEquals(HttpProtocolVersion.HTTP_2_0, r.version, host)
                    }
                    client(Http3Discovery.H3Only).use { c ->
                        val r = c.get("https://$host:$port/")
                        assertEquals("HTTP/3", body(r.bodyAsText(), token), host)
                    }
                }
            }
        }

    @Test fun plainConnectorWithoutHostServesIpv4AndIpv6() =
        serverTest {
            startEverywhere({
                plainConnector { port = 0 }
                http3 { enabled = false }
            }) { port, token ->
                val hosts = if (ipv6Bindable() && ipv6Loopback()) listOf("127.0.0.1", "[::1]") else listOf("127.0.0.1")
                for (host in hosts) {
                    client(null).use { c ->
                        assertEquals("HTTP/1.1", body(c.get("http://$host:$port/").bodyAsText(), token), host)
                    }
                }
            }
        }

    /**
     * An IPv4 client of a host-less connector arrives on the dual-stack socket as `::ffff:127.0.0.1`; the call sees the IPv4
     * address it is, on every protocol and platform (Kotlin/Native unmaps it, the JDK does so itself), so an access list or a
     * log written for `127.0.0.1` matches. An IPv6 client stays IPv6.
     */
    @Test fun ipv4ClientOfAHostlessConnectorIsSeenAsIpv4() =
        h3ServerTest {
            startEverywhere({
                tlsConnector /* wildcard on purpose: the default bind is the subject */ {
                    tls { identity = ServerFixtures.identity() }
                    port = 0
                }
            }) { port, token ->
                val v4 = listOf("127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1")
                val v6 = listOf("::1", "::1", "::1", "::1")
                client(null).use { c ->
                    assertEquals(v4, addresses(c, "https://127.0.0.1:$port/addresses", token), "HTTP/2")
                    if (ipv6Bindable() && ipv6Loopback()) assertEquals(v6, addresses(c, "https://[::1]:$port/addresses", token), "HTTP/2")
                }
                // HTTP/3: the local address is the one the client sent to, as the accelerated UDP socket reports it on the
                // JVM and Native alike (IP_PKTINFO / IPV6_PKTINFO, unmapped), never the wildcard the socket is bound to
                client(Http3Discovery.H3Only).use { c ->
                    assertEquals(v4, addresses(c, "https://127.0.0.1:$port/addresses", token), "HTTP/3")
                    if (ipv6Bindable() && ipv6Loopback()) assertEquals(v6, addresses(c, "https://[::1]:$port/addresses", token), "HTTP/3")
                }
            }
        }

    /** The same over cleartext HTTP/1.1 on a plain connector without a host. */
    @Test fun ipv4ClientOfAHostlessPlainConnectorIsSeenAsIpv4() =
        serverTest {
            startEverywhere({
                plainConnector { port = 0 }
                http3 { enabled = false }
            }) { port, token ->
                client(null).use { c ->
                    assertEquals(
                        listOf("127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"),
                        addresses(c, "http://127.0.0.1:$port/addresses", token),
                    )
                    if (ipv6Bindable() && ipv6Loopback()) {
                        assertEquals(listOf("::1", "::1", "::1", "::1"), addresses(c, "http://[::1]:$port/addresses", token))
                    }
                }
            }
        }

    /** `remoteHost remoteAddress localHost localAddress` of a call to [url], checked to come from this server ([token]). */
    private suspend fun addresses(
        c: HttpClient,
        url: String,
        token: String,
    ): List<String> {
        val words = c.get(url).bodyAsText().split(' ')
        if (words.first() != token) throw TokenMismatch("another server answered: $words")
        return words.drop(1)
    }

    /**
     * A host without IPv6 (Windows with it turned off, a kernel without it, `java.net.preferIPv4Stack`): a host-less connector
     * binds `0.0.0.0` instead, says so at Info, and serves its IPv4 clients over TCP and UDP alike (the seam stands in for
     * `ipv6Bindable() = false`).
     */
    @Test fun hostlessConnectorsFallBackToIpv4WithoutIpv6() =
        h3ServerTest {
            val log = CapturedLog()
            val server =
                kuicksilverServer(log, configure = {
                    tlsConnector /* wildcard on purpose: the default bind is the subject */ {
                        tls { identity = ServerFixtures.identity() }
                        port = 0
                    }
                    plainConnector { port = 0 }
                    ipv6BindableForTest = false
                    shutdownGracePeriod = 0
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(false)
            try {
                assertEquals(listOf("0.0.0.0", "0.0.0.0"), server.engine.resolvedConnectors().map { it.host })
                assertEquals(
                    2,
                    log.infos.count { "no IPv6 on this host, so every interface is every IPv4 one (0.0.0.0)" in it },
                    "${log.infos}",
                )
            } finally {
                server.stopSuspend(0, 500)
            }
            startEverywhere({
                tlsConnector /* wildcard on purpose: the default bind is the subject */ {
                    tls { identity = ServerFixtures.identity() }
                    port = 0
                }
                ipv6BindableForTest = false
            }) { port, token ->
                client(null).use { c -> assertEquals("HTTP/2", body(c.get("https://127.0.0.1:$port/").bodyAsText(), token)) }
                client(Http3Discovery.H3Only).use { c ->
                    assertEquals("HTTP/3", body(c.get("https://127.0.0.1:$port/").bodyAsText(), token))
                }
            }
        }

    /**
     * A host whose dual-stack UDP socket gets no Don't Fragment on its IPv4 half (RFC 9000 section 14: "In IPv4, the Don't
     * Fragment (DF) bit MUST be set if possible"; the hook stands in for that refusal, which the C tests force in `ksl` itself):
     * the host-less connector's HTTP/3 socket is two on one port, IPv6-only on `::` and AF_INET on 0.0.0.0, says so once at
     * Info, and serves HTTP/3 over IPv4 and over IPv6 on that port, each with DF (owner decision: every interface of both
     * families; two sockets where one dual-stack socket cannot be had). The client's own wildcard sockets are split too.
     * Every platform with the accelerated socket (Linux, Android, Apple, Windows).
     */
    @Test fun http3ServesBothFamiliesOnTwoSocketsWithoutDfOnTheIpv4Half() =
        h3ServerTest {
            if (!datagramIoSplitSupportedForTest()) return@h3ServerTest
            datagramIoSplitForTest = true
            try {
                // this server's own QUIC log, every level: the line is Info once per process and Debug after (another split
                // socket in the same process may have taken the Info), so the line itself is counted, not its level
                val quicLines =
                    kotlin.concurrent.atomics
                        .AtomicReference(emptyList<Pair<LogLevel, String>>())
                val own =
                    object : KuicksilverLogger {
                        override fun isEnabled(level: LogLevel): Boolean = true

                        override fun log(
                            level: LogLevel,
                            message: String,
                            cause: Throwable?,
                        ) {
                            quicLines.update { it + (level to message) }
                        }
                    }
                val server =
                    kuicksilverServer(null, configure = {
                        tlsConnector /* wildcard on purpose: the default bind is the subject */ {
                            tls { identity = ServerFixtures.identity() }
                            port = 0
                        }
                        observability { logger = own }
                        shutdownGracePeriod = 0
                    }) { routing { get("/") { call.respondText("ok") } } }
                server.startSuspend(false)
                try {
                    val port =
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port
                    val lines = quicLines.load()
                    assertEquals(
                        1,
                        lines.count { (level, m) ->
                            (level == LogLevel.Info || level == LogLevel.Debug) &&
                                ":$port uses two sockets (IPv6-only and IPv4) on one port" in m
                        },
                        "$lines",
                    )
                    assertTrue(lines.none { (level, m) -> level >= LogLevel.Warn && "Don't Fragment" in m }, "no warning about DF: $lines")
                } finally {
                    server.stopSuspend(0, 500)
                }
                startEverywhere({
                    tlsConnector /* wildcard on purpose: the default bind is the subject */ {
                        tls { identity = ServerFixtures.identity() }
                        port = 0
                    }
                }) { port, token ->
                    val hosts = if (ipv6Bindable() && ipv6Loopback()) listOf("127.0.0.1", "[::1]") else listOf("127.0.0.1")
                    for (host in hosts) {
                        client(Http3Discovery.H3Only).use { c ->
                            assertEquals("HTTP/3", body(c.get("https://$host:$port/").bodyAsText(), token), host)
                            // the call's local address is the one the client sent to, as on the dual-stack socket
                            val v = addresses(c, "https://$host:$port/addresses", token)
                            assertEquals(host.trim('[', ']'), v[2], "local host over $host")
                        }
                    }
                }
            } finally {
                datagramIoSplitForTest = false
            }
        }

    @Test fun connectorWithoutHostReportsTheWildcard() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    plainConnector { port = 0 }
                    http3 { enabled = false }
                    shutdownGracePeriod = 0
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(false)
            try {
                val c = server.engine.resolvedConnectors().first()
                assertEquals(if (ipv6Bindable()) "::" else "0.0.0.0", c.host)
            } finally {
                server.stopSuspend(0, 500)
            }
        }

    private companion object {
        const val ATTEMPTS = 5
    }
}
