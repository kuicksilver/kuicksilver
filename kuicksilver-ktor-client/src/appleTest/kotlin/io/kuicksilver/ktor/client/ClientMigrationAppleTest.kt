// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.MigrationEvent
import kotlinx.coroutines.channels.Channel
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** `Http3ConnectionMigration.followDefaultNetwork()` (NWPathMonitor) under the engine: connections set up with it serve as usual. */
@OptIn(ExperimentalKuicksilverApi::class)
class ClientMigrationAppleTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun connectionFollowingTheDefaultNetworkServes() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText(call.request.httpVersion) } } }
            val heard = Channel<MigrationEvent<*>>(Channel.UNLIMITED)
            try {
                testClient(Http3DiscoveryMode.H3Only, engine = {
                    eventListener =
                        object : KuicksilverEventListener() {
                            override fun connectionMigrated(
                                origin: String,
                                event: MigrationEvent<*>,
                            ) {
                                heard.trySend(event)
                            }
                        }
                    http3 { connectionMigration = Http3ConnectionMigration.followDefaultNetwork() }
                }).use { c ->
                    repeat(3) { assertEquals("HTTP/3", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                    // the network did not change: nothing moved, nothing failed
                    assertTrue(heard.tryReceive().isFailure, "${heard.tryReceive().getOrNull()}")
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
