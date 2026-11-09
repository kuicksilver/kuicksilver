// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.server.application.call
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A response whose content is a channel that failed (`call.respond(channel)`, a proxy relaying an upstream body that was
 * cut) is cut short, never ended as complete. Ktor's `respondFromChannel` copies with ktor-io's `copyTo`, which stops on a
 * channel failed with a cause as on one that ended, without throwing, when the failure was there before its read (it
 * throws only when it was waiting for content at that moment); without a Content-Length the engine then ended the
 * response cleanly: the last chunk on HTTP/1.1 (RFC 9112 section 7.1), a FIN on HTTP/3 (RFC 9114 section 4.1), so the
 * client took the cut body for the whole one.
 */
class ServerFailedChannelResponseTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Some content, then a failure recorded before anything reads it: ktor-io's `copyTo` answers it as an end. */
    private suspend fun failedChannel(): ByteReadChannel {
        val ch = ByteChannel()
        ch.writeStringUtf8("the start of the content")
        ch.flush()
        ch.cancel(IOException("the upstream body was cut"))
        return ch
    }

    private suspend fun <T> withServer(block: suspend (Int) -> T): T {
        val (server, port) = tlsServer { routing { get("/failed") { call.respond(failedChannel()) } } }
        try {
            return block(port)
        } finally {
            server.stop(100, 500)
        }
    }

    /** RFC 9112 section 7.1: the last chunk ends a chunked body; a body that failed must not get one. */
    @Test fun negative_aFailedContentChannelGetsNoLastChunkOverHttp11() =
        serverTest {
            withServer { port ->
                val resp =
                    withTimeout(10.seconds) {
                        // a reset while the client reads fails the read: also a response that is not complete
                        runCatching { rawHttp(port, "GET /failed HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\n") }.getOrNull()
                    }
                if (resp != null) {
                    assertTrue(resp.isEmpty() || resp.startsWith("HTTP/1.1 200 "), resp)
                    assertFalse(resp.endsWith("\r\n0\r\n\r\n"), "a failed body ended with the last chunk: $resp")
                }
            }
        }

    /** RFC 9114 section 4.1: a response stream that does not carry a complete response is reset, not ended with a FIN. */
    @Test fun negative_aFailedContentChannelIsNotEndedOverHttp3() =
        h3ServerTest {
            withServer { port ->
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                    try {
                        withTimeout(10.seconds) {
                            assertFails("a failed body ended with a FIN") {
                                c.request(http3Request("GET", "server.test", "/failed")).body.readFullBody()
                            }
                        }
                    } finally {
                        c.close()
                    }
                } finally {
                    ep.close()
                }
            }
        }
}
