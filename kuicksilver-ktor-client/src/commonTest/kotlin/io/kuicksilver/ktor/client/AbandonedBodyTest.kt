// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.copyTo
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlinx.io.Buffer
import kotlinx.io.Sink
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/**
 * A response body the client leaves halfway (found by the soak harness): the server's handler, still writing a long body,
 * must end once the client is gone, over HTTP/1.1 and over HTTP/3. A handler that waits forever for a reader holds its
 * connection, its socket and the body it buffered.
 */
@OptIn(ExperimentalAtomicApi::class)
class AbandonedBodyTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun abandon(discovery: Http3DiscoveryMode) {
        val active = AtomicInt(0)
        val chunk = ByteArray(16 * 1024)
        val (server, port) =
            testServer {
                routing {
                    get("/stream") {
                        active.incrementAndFetch()
                        try {
                            call.respondBytesWriter(ContentType.Application.OctetStream) {
                                repeat(1024) {
                                    writeFully(chunk)
                                    flush()
                                }
                            }
                        } finally {
                            active.decrementAndFetch()
                        }
                    }
                }
            }
        try {
            testClient(discovery).use { c ->
                repeat(3) {
                    c.prepareGet("https://127.0.0.1:$port/stream").execute { r ->
                        val ch = r.bodyAsChannel()
                        val buf = ByteArray(16 * 1024)
                        var read = 0
                        while (read < 256 * 1024) read += ch.readAvailable(buf, 0, buf.size).also { check(it >= 0) }
                    }
                }
                val ended = withTimeoutOrNull(10.seconds) { while (active.load() != 0) yield() }
                assertEquals(0, active.load(), "server handlers still writing abandoned bodies (ended=${ended != null})")
            }
        } finally {
            server.stop(100, 500)
        }
    }

    /**
     * `execute {}` returns when the application left the body while Ktor's `bodyAsChannel()` copier waits for room: that
     * copier (a coroutine of the client, holding a child job of the response until it ends) copies the raw body into the
     * channel the application reads, and once a megabyte waits there unread it suspends on the full channel. `execute`
     * cancels the raw body and joins the call's job: cancelling the raw body does not wake a copier that waits on its
     * destination, so the call hung forever (found by the soak harness; the copier is fast enough only under load). The
     * copier is modelled here by the same construct with a destination that stops taking bytes: deterministic.
     */
    @OptIn(InternalAPI::class)
    private suspend fun leaveWithStuckCopier(discovery: Http3DiscoveryMode) {
        val chunk = ByteArray(16 * 1024)
        val (server, port) =
            testServer {
                routing {
                    get("/stream") {
                        call.respondBytesWriter(ContentType.Application.OctetStream) {
                            repeat(1024) {
                                writeFully(chunk)
                                flush()
                            }
                        }
                    }
                }
            }
        val copiers = CoroutineScope(Dispatchers.Default)
        try {
            testClient(discovery).use { c ->
                val returned =
                    withTimeoutOrNull(10.seconds) {
                        c.prepareGet("https://127.0.0.1:$port/stream").execute { r ->
                            val full = CompletableDeferred<Unit>()
                            val holder = Job(r.coroutineContext.job) // as DefaultTransform's responseJobHolder
                            copiers.launch {
                                try {
                                    r.rawContent.copyTo(FillsUp(64 * 1024, full))
                                } finally {
                                    holder.complete()
                                }
                            }
                            full.await() // the copier now waits for room that never comes; the application leaves
                        }
                    }
                assertNotNull(returned, "execute {} did not return after the body was left")
            }
        } finally {
            copiers.cancel()
            server.stop(100, 500)
        }
    }

    /** Takes [capacity] bytes, then completes [full] and never takes more: an application channel nobody reads. */
    @OptIn(InternalAPI::class)
    private class FillsUp(
        private val capacity: Long,
        private val full: CompletableDeferred<Unit>,
    ) : ByteWriteChannel {
        private val buffer = Buffer()
        private var taken = 0L

        override val isClosedForWrite: Boolean get() = false

        override val closedCause: Throwable? get() = null

        override val writeBuffer: Sink get() = buffer

        override suspend fun flush() {
            taken += buffer.size
            buffer.clear()
            if (taken >= capacity) {
                full.complete(Unit)
                awaitCancellation()
            }
        }

        override suspend fun flushAndClose() = flush()

        override fun cancel(cause: Throwable?) {}
    }

    @Test fun leftBodyWithStuckCopierEndsCallH1() = clientTest { leaveWithStuckCopier(Http3DiscoveryMode.H1Only) }

    @Test fun leftBodyWithStuckCopierEndsCallH3() = h3Test { leaveWithStuckCopier(Http3DiscoveryMode.H3Only) }

    @Test fun abandonedBodyEndsServerHandlerH1() = clientTest { abandon(Http3DiscoveryMode.H1Only) }

    @Test fun abandonedBodyEndsServerHandlerH3() = h3Test { abandon(Http3DiscoveryMode.H3Only) }
}
