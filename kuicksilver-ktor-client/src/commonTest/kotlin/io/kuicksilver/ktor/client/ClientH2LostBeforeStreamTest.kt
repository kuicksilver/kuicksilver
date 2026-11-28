// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A new HTTP/2 connection whose transport is lost before the request got its stream, by something other than the
 * server's refusal of this client in the handshake (here this side's end of the TCP socket, as a reset or a truncation
 * ends it): the TCP setup failed, so the request, never sent, goes again (RFC 9113 section 8.7, as after its stream), and
 * in a race HTTP/3 may still win. [io.kuicksilver.ktor.client.h1.H1Pool.afterH2StartForTest] ends the first connection
 * before the pool hands it out; the refusal itself is ClientMissingCertificateTest's.
 */
class ClientH2LostBeforeStreamTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun withServer(block: suspend (port: Int) -> Unit) {
        val (server, port) =
            testServer(configure = { http2 { enabled = true } }) {
                routing { get("/") { call.respondText("ok ${call.request.httpVersion}") } }
            }
        try {
            block(port)
        } finally {
            server.stopSuspend(100, 1000)
        }
    }

    /** Over TCP alone: the call is repeated on a new connection, once, and served there over HTTP/2. */
    @Test fun aLossBeforeTheFirstStreamIsRepeated() =
        clientTest {
            withServer { port ->
                val retries = AtomicReference(emptyList<Throwable>())
                testClient(engine = {
                    observability {
                        eventListener =
                            object : KuicksilverEventListener() {
                                override fun retry(
                                    request: HttpRequestData,
                                    attempt: Int,
                                    cause: Throwable,
                                ) {
                                    while (true) {
                                        val l = retries.load()
                                        if (retries.compareAndSet(l, l + cause)) break
                                    }
                                }
                            }
                    }
                }).use { c ->
                    val started = AtomicInt(0)
                    (c.engine as KuicksilverEngine).h1.afterH2StartForTest = { client, tcp ->
                        if (started.fetchAndAdd(1) == 0) {
                            tcp.close()
                            client.awaitClosed()
                        }
                    }
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_2_0, r.version)
                    assertEquals("ok HTTP/2", r.bodyAsText())
                    assertEquals(2, started.load(), "a second connection served the repeat")
                    val cause = retries.load().singleOrNull()
                    assertIs<Http2Exception.ConnectionClosed>(cause, "one retry, for the lost connection: ${retries.load()}")
                }
            }
        }

    /**
     * In a race (Preferred): the TCP side's connection is lost before the request got its stream, and only then may the
     * HTTP/3 setup start ([io.kuicksilver.ktor.client.h3.H3Pool.beforeSetupForTest]): the TCP setup failed, HTTP/3 wins the
     * race and serves the call.
     */
    @Test fun aLossBeforeTheFirstStreamLetsHttp3WinTheRace() =
        h3Test {
            withServer { port ->
                testClient(Http3Discovery.Preferred).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val tcpLost = CompletableDeferred<Unit>()
                    engine.h3.beforeSetupForTest = { tcpLost.await() }
                    engine.h1.afterH2StartForTest = { client, tcp ->
                        tcp.close()
                        client.awaitClosed()
                        tcpLost.complete(Unit)
                    }
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals("ok HTTP/3", r.bodyAsText())
                    assertTrue(tcpLost.isCompleted, "the TCP side was lost first")
                    assertNotNull(r.kuicksilverDiagnostics)
                }
            }
        }
}
