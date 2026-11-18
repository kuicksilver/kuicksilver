// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h2

import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.ktor.server.H2cMode
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.ktor.server.RawFrame
import io.kuicksilver.ktor.server.RawH2Client
import io.kuicksilver.ktor.server.kuicksilverServer
import io.kuicksilver.ktor.server.serverTest
import io.kuicksilver.ktor.server.tlsServer
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The stop racing the client preface (RFC 9113 sections 3.4 and 6.8): a client whose preface and first request arrive as
 * the server starts to stop. The core reads on its own, so it may have taken the request when the stop wins the wait for
 * the preface; that request is then served (or, had nothing been taken, the GOAWAY says last stream 0), never left
 * unanswered under a GOAWAY that names it. The hook holds the wait until the stop began and the core took stream 1.
 */
class H2PrefaceDrainRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun KuicksilverApplicationEngine.Configuration.holdUntilStopping() {
        h2BeforePrefaceRaceForTest = { c, draining ->
            c.requestsTaken.first { it >= 1 } // the preface and the GET were read, stream 1 taken
            draining.join() // and the server is stopping
        }
    }

    private suspend fun run(
        server: EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>,
        port: Int,
        tls: Boolean,
    ) = coroutineScope {
        val raw = if (tls) RawH2Client.connect(port) else RawH2Client.connectPlain(port)
        raw.use {
            val get =
                listOf(":method" to "GET", ":scheme" to if (tls) "https" else "http", ":authority" to "server.test", ":path" to "/")
            // the preface, SETTINGS and the GET in one write
            raw.write(
                RawH2Client.PREFACE + RawH2Client.frame(RawFrame.SETTINGS, 0, 0) +
                    RawH2Client.frame(RawFrame.HEADERS, 0x5, 1, RawH2Client.block(get)),
            )
            withTimeout(10.seconds) {
                server.engine.h2Live.count
                    .first { it == 1 }
            }
            val stop = async { server.stopSuspend(10_000, 15_000) }
            val frames =
                withTimeout(20.seconds) {
                    buildList {
                        while (true) add(raw.readFrame() ?: break)
                    }
                }
            val answered = frames.any { it.stream == 1 && it.type == RawFrame.HEADERS }
            assertTrue(answered, "stream 1 was taken by the core, so it must be answered: $frames")
            val t =
                kotlin.time.TimeSource.Monotonic
                    .markNow()
            raw.close()
            withTimeout(20.seconds) { stop.await() }
            assertTrue(t.elapsedNow() < 5.seconds, "the stop waited ${t.elapsedNow()} after the exchange")
        }
    }

    @Test fun negative_aRequestTakenAsTheStopWinsIsServedOverH2c() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                        h2c = H2cMode.Only
                    }
                    http3 = false
                    holdUntilStopping()
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(wait = false)
            run(
                server,
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port,
                tls = false,
            )
        }

    @Test fun negative_aRequestTakenAsTheStopWinsIsServedOverTls() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http2 = true
                    http3 = false
                    holdUntilStopping()
                }) { routing { get("/") { call.respondText("ok") } } }
            run(server, port, tls = true)
        }
}
