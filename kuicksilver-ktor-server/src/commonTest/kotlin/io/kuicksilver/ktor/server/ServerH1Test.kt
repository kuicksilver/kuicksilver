// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.engine.ConnectorType
import io.ktor.server.engine.EngineConnectorBuilder
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.TlsException
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.delay
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ServerH1Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val get = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"

    @Test fun getOverTls() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get(
                            "/",
                        ) { call.respondText("ok ${call.request.httpVersion} ${call.request.local.scheme}") }
                    }
                }
            try {
                assertTrue(port > 0)
                val resp = rawHttp(port, get)
                assertTrue(resp.startsWith("HTTP/1.1 200"), resp)
                assertTrue(resp.endsWith("ok HTTP/1.1 https"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun keepAliveTwoRequests() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("p=${call.request.local.remotePort}") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\n\r\n$get")
                val bodies = Regex("p=(\\d+)").findAll(resp).map { it.groupValues[1] }.toList()
                assertEquals(2, bodies.size, resp)
                assertEquals(bodies[0], bodies[1])
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun chunkedResponse() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            call.respondBytesWriter {
                                writeStringUtf8("a")
                                flush()
                                writeStringUtf8("b")
                            }
                        }
                    }
                }
            try {
                val resp = rawHttp(port, get)
                assertTrue(resp.contains("Transfer-Encoding: chunked"), resp)
                assertTrue(resp.contains("1\r\na\r\n"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun plainHttpConnector() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("plain ${call.request.local.scheme}") } } }
            server.startSuspend(false)
            try {
                val resp =
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        get,
                        tls = null,
                    )
                assertTrue(resp.endsWith("plain http"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun identityTurnsPortConnectorIntoTls() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    identity =
                        ServerFixtures.identity()
                }) { routing { get("/") { call.respondText("tls ${call.request.local.scheme}") } } }
            server.startSuspend(false)
            try {
                val resp =
                    rawHttp(
                        server.engine
                            .resolvedConnectors()
                            .first()
                            .port,
                        get,
                    )
                assertTrue(resp.endsWith("tls https"), resp)
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun handshakeFailureClosesOnlyThatConnection() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            try {
                assertFailsWith<TlsException> {
                    rawHttp(
                        port,
                        get,
                        ServerFixtures.clientTls(trust = TrustConfig.AnchoredCa(listOf(io.kuicksilver.tls.Certificate(TestCerts.otherCa)))),
                    )
                }
                assertTrue(rawHttp(port, get).endsWith("ok"))
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun peerCertificatesOptionalClientAuth() =
        serverTest {
            val (server, port) =
                tlsServer(connector = {
                    clientAuth = ClientAuth.Optional
                    trust =
                        TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
                }) {
                    routing { get("/") { call.respondText("certs=${call.request.peerCertificates.size}") } }
                }
            try {
                rawHttp(port, get).let { assertTrue(it.endsWith("certs=0"), it) }
                val withCert =
                    ServerFixtures.clientTls(
                        identity = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf()),
                    )
                rawHttp(port, get, withCert).let { assertTrue(!it.endsWith("certs=0"), it) } // the validated chain: leaf and CA
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun stopClosesThePort() =
        serverTest {
            val (server, port) =
                tlsServer {
                    routing {
                        get("/") {
                            delay(50)
                            call.respondText("ok")
                        }
                    }
                }
            assertTrue(rawHttp(port, get).endsWith("ok"))
            server.stop(100, 500)
            assertFailsWith<Throwable> { rawHttp(port, get) }
        }

    /**
     * A connector on `::1` listens on `::1` only. Ktor 3.6.0's Kotlin/Native bind never copied the address into `sockaddr_in6`,
     * so this connector listened on `::`: every IPv6 interface and, dual-stack on Linux and Apple, IPv4 too. An IPv4 connect
     * to its port (another address of this host) must be refused (docs/upstream/ktor-native-ipv6.md).
     */
    @Test fun negative_ipv6ConnectorListensOnItsAddressOnly() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connector {
                        host = "::1"
                        port = 0
                    }
                }) { routing { get("/") { call.respondText("reached") } } }
            if (runCatching { server.startSuspend(false) }.isFailure) {
                println("negative_ipv6ConnectorListensOnItsAddressOnly skipped: needs an IPv6 loopback")
                return@serverTest
            }
            try {
                val port =
                    server.engine
                        .resolvedConnectors()
                        .first()
                        .port
                val v4 = runCatching { rawHttp(port, get, tls = null) }
                assertTrue(v4.isFailure, "127.0.0.1:$port reached the connector bound to ::1: ${v4.getOrNull()}")
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun unsupportedConnectorFailsWithConfig() =
        serverTest {
            val server =
                embeddedServer(Kuicksilver, configure = {
                    connectors.add(
                        EngineConnectorBuilder(ConnectorType.HTTPS).apply {
                            host =
                                "127.0.0.1"
                            ; port = 0
                        },
                    )
                }) { }
            assertFailsWith<TlsException.Config> { server.startSuspend(false) }
            runCatching { server.stop(10, 10) }
        }
}
