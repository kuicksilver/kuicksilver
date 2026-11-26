// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.network.sockets.ConnectTimeoutException
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.request.get
import io.ktor.network.selector.SelectorManager
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A `ConnectTimeoutException` names the connect timeout that fired, also when it is the engine's own `connectTimeout`
 * and Ktor's `HttpTimeout` is not installed: Ktor's `ConnectTimeoutException(request, cause)` reads the plugin's alone and
 * said `connect_timeout=unknown ms`.
 */
class ConnectTimeoutMessageTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun assertNames(
        millis: Long,
        e: ConnectTimeoutException,
    ) {
        assertTrue("connect_timeout=$millis ms" in e.message.orEmpty(), "${e.message}")
    }

    @Test fun aNameLookupTimeoutNamesTheEnginesConnectTimeout() =
        clientTest {
            testClient(engine = {
                connectTimeout = 300.milliseconds
                network { dns = Dns { awaitCancellation() } }
            }).use { c ->
                assertNames(300, assertFailsWith<ConnectTimeoutException> { c.get("https://never.test/") })
            }
        }

    @Test fun aWebSocketsLookupTimeoutNamesTheEnginesConnectTimeout() =
        clientTest {
            testClient(engine = {
                connectTimeout = 300.milliseconds
                network { dns = Dns { awaitCancellation() } }
            }, block = { install(WebSockets) }).use { c ->
                assertNames(300, assertFailsWith<ConnectTimeoutException> { c.webSocket("wss://never.test/") {} })
            }
        }

    @Test fun httpTimeoutsConnectTimeoutIsTheOneNamed() =
        clientTest {
            testClient(engine = {
                connectTimeout = 30.seconds
                network { dns = Dns { awaitCancellation() } }
            }, block = { install(HttpTimeout) { connectTimeoutMillis = 250 } }).use { c ->
                assertNames(250, assertFailsWith<ConnectTimeoutException> { c.get("https://never.test/") })
            }
        }

    /** A WebTransport session's connect timeout names the session's URL, as every other call's does. */
    @Test fun aWebTransportConnectTimeoutNamesTheUrl() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val (udp, port) = udpOn(selector, 0)
            try {
                testClient(Http3Discovery.H3Only, engine = {
                    connectTimeout = 400.milliseconds
                    quicHandshakeTimeoutForTest = 30.seconds
                }).use { c ->
                    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                    val e = assertFailsWith<ConnectTimeoutException> { c.webTransport("https://127.0.0.1:$port/wt?x=1") }
                    assertNames(400, e)
                    assertTrue("url=https://127.0.0.1:$port/wt?x=1" in e.message.orEmpty(), "${e.message}")
                }
            } finally {
                udp.close()
                selector.close()
            }
        }

    @Test fun aQuicSetupTimeoutNamesTheEnginesConnectTimeout() =
        clientTest {
            val selector = SelectorManager(Dispatchers.IO)
            val (udp, port) = udpOn(selector, 0)
            try {
                testClient(Http3Discovery.H3Only, engine = {
                    connectTimeout = 400.milliseconds
                    quicHandshakeTimeoutForTest = 30.seconds
                }).use { c ->
                    assertNames(400, assertFailsWith<ConnectTimeoutException> { c.get("https://127.0.0.1:$port/") })
                }
            } finally {
                udp.close()
                selector.close()
            }
        }
}
