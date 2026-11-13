// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.client.h3.H3Target
import io.kuicksilver.ktor.network.TcpAddress
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

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
    @Test fun originsAtOneAddressGetAConnectionAndTlsConfigurationEach() =
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
     * The open gap this pins: the key holds the destination's name, not its address. One origin reached under two names
     * (its own and an `Alt-Svc` or HTTPS-record target) that resolve to the same address and port gets two connections with
     * the same configuration, which the section's SHOULD asks to avoid (docs/spec/rfc/9114.md, section 3.3).
     */
    @Test fun poolKeysByDestinationNameNotAddress() {
        val origin = H3Target("server.test", "server.test", 443)
        assertEquals(origin.key, H3Target("server.test", "server.test", 443).key)
        assertNotEquals(origin.key, H3Target("server.test", "alt.server.test", 443).key, "another name of the same address")
        assertNotEquals(origin.key, H3Target("a.wild.test", "server.test", 443).key, "another origin: another TLS configuration")
    }
}
