// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocketSession
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.websocket.CloseReason
import io.ktor.websocket.close
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsRole
import io.kuicksilver.tls.tlsConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * A WebSocket over HTTP/3 whose CONNECT is answered as the connect timeout fires (the timeout lands on another thread after
 * the answer was read, before the deadline's scope completed) is connected and used: the stream exists on both sides, and
 * dropping it left it open with nobody to end it. The QUIC handshake and the CONNECT before the hook must end within the
 * connect timeout for the race to happen: a run whose hook was not reached does not count, and the next one gets the
 * timeout doubled.
 */
class H3WebSocketConnectRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Volatile private var reached = false

    @Test fun negative_aConnectAnsweredAsTheTimeoutFiresIsUsed() =
        h3Test {
            var timeout = 2.seconds
            repeat(4) {
                if (attempt(timeout)) return@h3Test
                timeout *= 2
            }
            fail("the QUIC handshake and the CONNECT never ended within ${timeout / 2}")
        }

    /** One run with a connect timeout of [timeout]: false when the hook was not reached before it fired. */
    private suspend fun attempt(timeout: Duration): Boolean {
        val serverTls =
            tlsConfig(TlsRole.Server) {
                alpn = listOf("h3")
                identity = TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())
            }
        val ep =
            Http3Endpoint.bind(
                InetSocketAddress("127.0.0.1", 0),
                QuicEndpointConfig
                    .Builder()
                    .apply { this.server = QuicServerConfig.Builder(serverTls).build() }
                    .build(),
                io.kuicksilver.http3.http3Settings { enableConnectProtocol = true },
            )
        return coroutineScope {
            val served =
                async {
                    val conn = ep.accept()
                    val s = conn.acceptRequest().acceptConnect()
                    readClientFrames(s.input)
                }
            try {
                testClient(
                    Http3DiscoveryMode.H3Only,
                    // the deadline of the CONNECT (and of the QUIC handshake before it)
                    engine = { connectTimeout = timeout },
                    block = { install(WebSockets) },
                ).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    reached = false
                    engine.h3.webSocketConnectedForTest = {
                        yield() // completes through a resumption, as the CONNECT's answer does; throws once the timeout fired
                        reached = true
                        val job = currentCoroutineContext().job
                        while (!job.isCancelled) Thread.onSpinWait() // the connect timeout fires meanwhile
                    }
                    // threw ConnectTimeoutException for a CONNECT the server had answered
                    val session = runCatching { c.webSocketSession("wss://127.0.0.1:${ep.localAddress.port}/ws") }
                    engine.h3.webSocketConnectedForTest = null
                    if (!reached) return@coroutineScope false
                    session.getOrThrow().close(CloseReason(4003, "raced"))
                    assertEquals(listOf("close 4003 raced"), withTimeout(20.seconds) { served.await() })
                    true
                }
            } finally {
                served.cancel()
                ep.close()
            }
        }
    }
}
