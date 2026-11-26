// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsIdentity
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The server code blocks of docs/guide/zero-rtt.md (markers `guide:zero-rtt:server`, `guide:zero-rtt:replayable`): the
 * samples build the engines (ServerH3Test and the client's ClientEarlyDataTest run early requests).
 */
class ZeroRttGuideSamplesTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val chainPem = TestCerts.toPem("CERTIFICATE", TestCerts.server)
    private val keyPem = TestCerts.toPem("PRIVATE KEY", TestCerts.serverKey)

    @Test fun serverSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:zero-rtt:server
        val server =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1" // a test reaches its servers over 127.0.0.1
                }
                http3 { earlyData { enabled = true } }
            }) {
                routing {
                    get("/") { call.respondText("early: ${call.request.receivedEarly}") }
                }
            }

        assertTrue(server.engine.configuration.http3.earlyData.enabled)
        identity.close()
    }

    @Test fun replayableSample() {
        val identity = TlsIdentity.fromPem(chainPem, keyPem.toCharArray())
        // guide:zero-rtt:replayable
        val policy =
            Http3EarlyDataPolicy.WaitForHandshake(replayable = { request ->
                request.method == "GET" && request.path.orEmpty().startsWith("/static/") // only these may run early
            })
        val narrowed =
            embeddedServer(Kuicksilver, configure = {
                tlsConnector {
                    tls { this.identity = identity }
                    port = 0
                    host = "127.0.0.1"
                }
                http3 {
                    earlyData {
                        enabled = true
                        this.policy = policy
                    }
                }
            }) {
                routing {
                    get("/feed") {
                        if (call.request.receivedEarly) { /* a replay is possible here: no side effects */ }
                        call.respondText("feed")
                    }
                }
            }

        assertSame(policy, narrowed.engine.configuration.http3.earlyData.policy)
        identity.close()
    }
}
