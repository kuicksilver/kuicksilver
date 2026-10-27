// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ServerTlsOverride
import kotlin.test.BeforeTest
import kotlin.test.Test
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

    /** QUIC cannot use a per-SNI identity: a connector with `sniSelector` serves HTTP/1.1, skips HTTP/3 and sends no Alt-Svc. */
    @Test fun h3SkippedForSniSelectorConnector() =
        serverTest {
            val log = CapturedLog()
            val (server, port) =
                tlsServer(connector = {
                    sniSelector = { ServerTlsOverride(ServerFixtures.identity()) }
                }, log = log) { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.endsWith("ok") && !resp.contains("Alt-Svc"), resp)
                log.assertLogged("WARN", "HTTP/3 is not served on", "sniSelector is not supported by QUIC")
            } finally {
                server.stop(100, 500)
            }
        }
}
