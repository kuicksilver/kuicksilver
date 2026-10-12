// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.server.receivedEarly
import io.kuicksilver.native.KslLoader
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 0-RTT between the Kuicksilver engines when both opt in (ADR-0015). */
@OptIn(ExperimentalKuicksilverApi::class)
class ClientEarlyDataTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun reconnectResumesWith0Rtt() =
        clientTest {
            val (server, port) =
                testServer(configure = { quicEarlyData = true }) {
                    routing {
                        get("/") { call.respondText("get early=${call.request.receivedEarly}") }
                        post("/") { call.respondText("post early=${call.request.receivedEarly}") }
                    }
                }
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = { http3 { earlyData = true } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val first = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, first.version)
                    assertEquals("get early=false", first.bodyAsText())
                    assertEquals("get early=false", c.get("https://127.0.0.1:$port/").bodyAsText()) // the ticket arrived meanwhile
                    assertEquals(
                        null,
                        engine.h3
                            .connectionsForTest()
                            .single()
                            .quic.earlyDataAccepted,
                        "a full handshake",
                    )
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    val again = c.get("https://127.0.0.1:$port/").bodyAsText()
                    assertTrue(again == "get early=true" || again == "get early=false", again) // early only when it beat the handshake
                    val conn = engine.h3.connectionsForTest().single()
                    conn.quic.awaitHandshake()
                    assertEquals(true, conn.quic.earlyDataAccepted, "the reconnect resumed with 0-RTT")
                    assertEquals("post early=false", c.post("https://127.0.0.1:$port/").bodyAsText(), "a POST never runs early")
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
