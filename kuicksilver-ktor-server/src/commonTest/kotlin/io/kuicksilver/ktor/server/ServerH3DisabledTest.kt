// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ServerH3DisabledTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Where a QUIC server cannot run (no accelerated socket on Native, ADR-0006) HTTP/1.1 keeps working and no Alt-Svc is sent. */
    @Test fun h3DisabledWhenQuicServerUnsupported() =
        serverTest {
            val log = CapturedLog()
            val (server, port) =
                tlsServer(configure = {
                    http3Bind =
                        { _, _, _ -> throw UnsupportedOperationException("no QUIC server on this platform") }
                }, log = log) { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.endsWith("ok") && !resp.contains("Alt-Svc"), resp)
                log.assertLogged("WARN", "HTTP/3 is not served on port", "no QUIC server on this platform")
            } finally {
                server.stop(100, 500)
            }
        }

    /** No DF, no QUIC: a UDP socket that cannot set Don't Fragment leaves the server on HTTP/1.1, without Alt-Svc. */
    @Test fun h3DisabledWithoutDontFragment() =
        serverTest {
            val log = CapturedLog()
            val (server, port) =
                tlsServer(configure = {
                    http3Bind =
                        { _, _, _ ->
                            throw io.kuicksilver.quic.QuicException
                                .DontFragmentUnavailable(null, "test: no DF")
                        }
                }, log = log) { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.endsWith("ok") && !resp.contains("Alt-Svc"), resp)
                log.assertLogged("WARN", "HTTP/3 is not served on port", "cannot set Don't Fragment")
                // visible in the engine's status, not only in the log
                val st = server.engine.http3Status.single()
                assertEquals(port, st.port)
                assertFalse(st.served)
                assertIs<io.kuicksilver.quic.QuicException.DontFragmentUnavailable>(st.reason)
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * HTTP/3 served for one address family only (no DF for the other): connections from that family get no Alt-Svc, the
     * others do.
     */
    @Test fun noAltSvcForTheFamilyWithoutDontFragment() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("ok") } } }
            try {
                assertTrue(
                    server.engine.http3Status
                        .single()
                        .served,
                )
                assertEquals(
                    null,
                    server.engine.http3Status
                        .single()
                        .notServedFamily,
                )
                val req = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"
                assertTrue(rawHttp(port, req).contains("Alt-Svc: h3=\":$port\""), "served for both: Alt-Svc")
                server.engine.h3NoDfFamily[port] = io.kuicksilver.quic.IpFamily.V4
                assertFalse(rawHttp(port, req).contains("Alt-Svc"), "an IPv4 client of a port without DF for IPv4")
                server.engine.h3NoDfFamily[port] = io.kuicksilver.quic.IpFamily.V6
                assertTrue(rawHttp(port, req).contains("Alt-Svc: h3=\":$port\""), "IPv4 is served when IPv6 is not")
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun peerFamilyCountsMappedAsIpv4() {
        assertEquals(
            io.kuicksilver.quic.IpFamily.V4,
            peerFamily(
                io.ktor.network.sockets
                    .InetSocketAddress("127.0.0.1", 1),
            ),
        )
        assertEquals(
            io.kuicksilver.quic.IpFamily.V4,
            peerFamily(
                io.ktor.network.sockets
                    .InetSocketAddress("::ffff:10.0.0.1", 1),
            ),
        )
        assertEquals(
            io.kuicksilver.quic.IpFamily.V6,
            peerFamily(
                io.ktor.network.sockets
                    .InetSocketAddress("::1", 1),
            ),
        )
        assertEquals(null, peerFamily(null))
    }
}
