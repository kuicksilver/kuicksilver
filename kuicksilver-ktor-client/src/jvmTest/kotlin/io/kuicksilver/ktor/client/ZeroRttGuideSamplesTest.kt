// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.ktor.server.receivedEarly
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionInfo
import io.kuicksilver.quic.ConnectionListener
import io.kuicksilver.quic.ZeroRttOutcome
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** The client code blocks of docs/guide/zero-rtt.md (markers `guide:zero-rtt:client*`), kept compiling and running. */
class ZeroRttGuideSamplesTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The page's client with its check: after a ticket arrived, a new HTTP/3 connection to the server resumes in 0-RTT. */
    @Test fun clientCheckSeesZeroRtt() =
        clientTest {
            val (server, port) =
                testServer(configure = { http3 { earlyData { enabled = true } } }) {
                    routing { get("/") { call.respondText("early: ${call.request.receivedEarly}") } }
                }
            val seen = CompletableDeferred<ZeroRttOutcome>()
            try {
                // guide:zero-rtt:client
                val client =
                    HttpClient(Kuicksilver) {
                        engine {
                            http3 { earlyData { enabled = true } }
                            // guide:zero-rtt:client-check
                            observability {
                                connectionListener =
                                    object : ConnectionListener {
                                        override fun onZeroRtt(
                                            connection: ConnectionInfo,
                                            outcome: ZeroRttOutcome,
                                        ) {
                                            println("0-RTT to ${connection.remoteAddress}: $outcome") // Accepted or Rejected
                                        }
                                    }
                            }
                        }
                    }
                client.close()

                HttpClient(Kuicksilver) {
                    engine {
                        tls { trust = ClientFixtures.trust }
                        http3 {
                            discovery = Http3Discovery.H3Only
                            earlyData { enabled = true }
                        }
                        observability {
                            connectionListener =
                                object : ConnectionListener {
                                    override fun onZeroRtt(
                                        connection: ConnectionInfo,
                                        outcome: ZeroRttOutcome,
                                    ) {
                                        seen.complete(outcome)
                                    }
                                }
                        }
                    }
                }.use { c ->
                    val url = "https://127.0.0.1:$port/"
                    val first = c.get(url)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, first.version)
                    assertEquals("early: false", first.bodyAsText())
                    c.get(url).bodyAsText() // the session ticket arrives after the handshake: one more round trip
                    c.closeHttp3Connections() // the next request opens a new connection, which resumes with the ticket
                    val again = c.get(url).bodyAsText()
                    assertEquals(ZeroRttOutcome.Accepted, withTimeout(10.seconds) { seen.await() })
                    println(again) // "early: true" when the request beat the handshake, else "early: false"
                }
            } finally {
                server.stopSuspend(100, 500)
            }
        }
}
