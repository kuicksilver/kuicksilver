// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.http.ContentType
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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

    @Test fun abandonedBodyEndsServerHandlerH1() = clientTest { abandon(Http3DiscoveryMode.H1Only) }

    @Test fun abandonedBodyEndsServerHandlerH3() = h3Test { abandon(Http3DiscoveryMode.H3Only) }
}
