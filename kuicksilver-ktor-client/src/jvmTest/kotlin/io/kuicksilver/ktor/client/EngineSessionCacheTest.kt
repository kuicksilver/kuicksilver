// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.tls.SessionCache
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** Each engine owns its TLS session cache: tickets never land in the process-wide cache, and closing the engine frees them. */
class EngineSessionCacheTest {
    @Test fun engineCloseDropsItsSessions() =
        clientTest {
            SessionCache.Default.clear()
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                val client = testClient()
                val engine = client.engine as KuicksilverEngine
                assertEquals("ok", client.get("https://127.0.0.1:$port/").bodyAsText())
                withTimeout(10.seconds) { while (engine.h1.sessions.size() == 0) yield() } // the ticket lands from the reader pump
                assertEquals(1, engine.h1.sessions.size(), "the ticket is in the engine's cache")
                assertEquals(0, SessionCache.Default.size(), "and not in the process-wide one")
                client.close()
                engine.cleanup.join()
                assertEquals(0, engine.h1.sessions.size(), "closing the engine drops its sessions")
            } finally {
                server.stop(100, 500)
            }
        }
}
