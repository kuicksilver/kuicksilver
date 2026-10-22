// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.ktor.utils.io.InternalAPI::class)

package io.kuicksilver.ktor.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngineBase
import io.ktor.client.engine.HttpClientEngineConfig
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.server.routing.routing
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.WebTransportCloseInfo
import io.kuicksilver.ktor.server.webTransport
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** `HttpClient.webTransport`: a WebTransport session on a dedicated HTTP/3 connection of the engine. */
class ClientWebTransportTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class OtherEngine : HttpClientEngineBase("other") {
        override val config: HttpClientEngineConfig = HttpClientEngineConfig()

        override suspend fun execute(data: HttpRequestData): HttpResponseData = error("not used")
    }

    private fun KuicksilverEngine.dedicated() = h3.dedicatedCount

    @Test fun echoAgainstKuicksilverServer() =
        h3Test {
            val (server, port) =
                testServer(configure = { webTransport = true }) {
                    routing {
                        webTransport("/wt") { session ->
                            val st = session.acceptBidi()
                            st.input.copyTo(st.output)
                            st.output.flushAndClose()
                            session.sendDatagram(session.receiveDatagram())
                            session.closed.await()
                        }
                    }
                }
            try {
                testClient().use { client ->
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    val st = session.openBidi()
                    st.output.writeFully("ping".encodeToByteArray())
                    st.output.flushAndClose()
                    assertEquals("ping", withTimeout(10.seconds) { st.input.readRemaining().readString() })
                    session.trySendDatagram(byteArrayOf(4, 2))
                    assertContentEquals(byteArrayOf(4, 2), withTimeout(10.seconds) { session.receiveDatagram() })
                    session.close(0, "done")
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** Each session has a connection of its own, outside the pool; closing the session closes it. */
    @Test fun closeClosesDedicatedConnection() =
        h3Test {
            val seen = CompletableDeferred<WebTransportCloseInfo>()
            val (server, port) =
                testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { seen.complete(it.closed.await()) } } }
            try {
                testClient().use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(1, engine.dedicated().value)
                    assertEquals(0, engine.h3.connectionsForProbe()) // not pooled
                    session.close(7, "bye")
                    withTimeout(10.seconds) { engine.dedicated().first { it == 0 } }
                    assertEquals(0, engine.h3.connectionsForProbe())
                    // the connection closed after the session's close reached the server, not instead of it
                    val info = withTimeout(10.seconds) { seen.await() }
                    assertEquals(7L to "bye", info.code to info.reason)
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    /** The server ending the session ends the dedicated connection too. */
    @Test fun serverCloseClosesDedicatedConnection() =
        h3Test {
            val (server, port) = testServer(configure = { webTransport = true }) { routing { webTransport("/wt") { } } }
            try {
                testClient().use { client ->
                    val engine = client.engine as KuicksilverEngine
                    val session = client.webTransport("https://127.0.0.1:$port/wt")
                    assertEquals(0L, withTimeout(10.seconds) { session.closed.await() }.code)
                    withTimeout(10.seconds) { engine.dedicated().first { it == 0 } }
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun serverWithoutWtFailsWithSettings() =
        h3Test {
            val (server, port) = testServer { routing { } }
            try {
                testClient().use { client ->
                    val engine = client.engine as KuicksilverEngine
                    assertFailsWith<Http3Exception.Settings> { client.webTransport("https://127.0.0.1:$port/wt") }
                    withTimeout(10.seconds) { engine.dedicated().first { it == 0 } } // the connection does not stay
                }
            } finally {
                server.stopSuspend(100, 1000)
            }
        }

    @Test fun negative_nonKuicksilverEngineFails() =
        clientTest {
            HttpClient(OtherEngine()).use { client ->
                assertFailsWith<IllegalStateException> { client.webTransport("https://example.com/wt") }
            }
        }

    @Test fun negative_plainHttpRefused() =
        clientTest {
            testClient().use { client ->
                assertFailsWith<IllegalArgumentException> { client.webTransport("http://127.0.0.1:1/wt") }
            }
        }
}
