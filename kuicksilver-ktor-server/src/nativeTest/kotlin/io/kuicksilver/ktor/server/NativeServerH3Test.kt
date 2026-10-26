// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readBuffer
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The engine serves HTTP/3 on Kotlin/Native where the accelerated UDP socket exists (Linux, Apple, Windows; ADR-0006). */
class NativeServerH3Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun h3ServedAndAdvertisedOnNative() =
        serverTest {
            val (server, port) = tlsServer { routing { get("/") { call.respondText("native h3") } } }
            try {
                val resp = rawHttp(port, "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n")
                assertTrue(resp.contains("Alt-Svc: h3=\":$port\""), resp)
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                    try {
                        val r = c.request(http3Request("GET", "server.test", "/"))
                        assertEquals(200, r.status)
                        assertEquals(
                            "native h3",
                            r.body
                                .readBuffer()
                                .readByteArray()
                                .decodeToString(),
                        )
                    } finally {
                        c.close()
                    }
                } finally {
                    ep.close()
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
