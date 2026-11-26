// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsText
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.job
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A qlog sink that only counts the traces opened and closed. The close of a trace for which [hold] answers true (asked
 * with the connection's ID at the close) blocks the endpoint loop that closes it until [release] (at most 5 s): what waits
 * for that close waits for it.
 */
internal class CountingQlogSink(
    private val hold: (odcidHex: String) -> Boolean = { false },
) : QlogSink {
    val opened = AtomicInt(0)
    val closed = AtomicInt(0)
    private val released = kotlinx.coroutines.CompletableDeferred<Unit>()

    fun release() {
        released.complete(Unit)
    }

    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace {
        opened.incrementAndFetch()
        return object : QlogTrace {
            override fun write(record: String) {}

            override fun close() {
                if (hold(odcidHex)) {
                    kotlinx.coroutines.runBlocking { kotlinx.coroutines.withTimeoutOrNull(5.seconds) { released.await() } }
                }
                closed.incrementAndFetch()
            }
        }
    }
}

/**
 * `client.engine.coroutineContext.job.join()` after `HttpClient.close()` (docs/guide/ktor.md, "Closing the client"):
 * it returns once the pools and endpoints are closed and every connection's qlog trace with them.
 */
class ClientCloseJoinTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun joiningTheEngineJobWaitsForEveryQlogTrace() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val sink = CountingQlogSink()
            try {
                testClient(Http3Discovery.H3Only, engine = { observability { qlog = sink } }).use { c ->
                    assertEquals("ok", c.get("https://127.0.0.1:$port/").bodyAsText())
                    assertEquals(1, sink.opened.load())
                    val job = c.engine.coroutineContext.job
                    assertFalse(job.isCompleted, "open until close()")
                    c.close() // returns at once: the cleanup runs after it
                    withTimeout(10.seconds) { job.join() }
                    assertEquals(sink.opened.load(), sink.closed.load(), "every trace closed by the time join() returned")
                    assertTrue((c.engine as KuicksilverEngine).cleanup.isCompleted)
                }
            } finally {
                server.stop(100, 500)
            }
        }

    @Test fun joiningWaitsForACallStillReadingItsBody() =
        h3Test {
            val (server, port) = testServer { routing { get("/") { call.respondText("ok") } } }
            val sink = CountingQlogSink()
            try {
                testClient(Http3Discovery.H3Only, engine = { observability { qlog = sink } }).use { c ->
                    val job = c.engine.coroutineContext.job
                    c.prepareGet("https://127.0.0.1:$port/").execute { r ->
                        c.close() // the call in flight finishes first, then the cleanup
                        assertFalse(job.isCompleted, "the cleanup waits for the call")
                        assertEquals("ok", r.bodyAsText())
                    }
                    withTimeout(10.seconds) { job.join() }
                    assertEquals(sink.opened.load(), sink.closed.load())
                }
            } finally {
                server.stop(100, 500)
            }
        }
}
