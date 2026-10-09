// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue

class ServerH3DisabledTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Where a QUIC server cannot run (Apple and Windows Native, ADR-0006) HTTP/1.1 keeps working and no Alt-Svc is sent. */
    @Test fun h3DisabledWhenQuicServerUnsupported() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http3Bind =
                        { _, _, _ -> throw UnsupportedOperationException("no QUIC server on this platform") }
                }) { routing { get("/") { call.respondText("ok") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.endsWith("ok") && !resp.contains("Alt-Svc"), resp)
            } finally {
                server.stop(100, 500)
            }
        }
}
