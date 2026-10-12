// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.delay
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** JVM-only: counts the receive threads of the JVM datagram transport (`NioDatagramIo`) through the thread stacks. */
class ClientUdpReleaseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Found by the vendored Ktor client contract tests: every closed client left its UDP receive loop parked on Dispatchers.IO. */
    @Test fun closingTheClientReleasesItsUdpSocket() =
        h3Test {
            fun receivers() =
                Thread.getAllStackTraces().values.count { st ->
                    st.any {
                        it.className.startsWith("io.kuicksilver.quic.NioDatagramIo") &&
                            it.methodName.startsWith("receive")
                    }
                }
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            try {
                testClient(Http3DiscoveryMode.H3Only).use { c -> assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText()) }
                delay(300)
                val baseline = receivers()
                repeat(6) {
                    testClient(Http3DiscoveryMode.H3Only).use { c ->
                        assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                    }
                }
                var now = receivers()
                var waited = 0
                while (now > baseline && waited < 3000) {
                    delay(100)
                    waited += 100
                    now = receivers()
                }
                assertTrue(now <= baseline, "UDP receive loops: $baseline before, $now after six closed clients")
            } finally {
                server.stop(100, 500)
            }
        }
}
