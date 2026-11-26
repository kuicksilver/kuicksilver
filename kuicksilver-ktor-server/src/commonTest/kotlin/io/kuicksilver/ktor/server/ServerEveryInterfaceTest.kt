// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
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
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.TrustConfig
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
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
                }) { routing { get("/") { call.respondText("$token ${call.request.local.version}") } } }
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
