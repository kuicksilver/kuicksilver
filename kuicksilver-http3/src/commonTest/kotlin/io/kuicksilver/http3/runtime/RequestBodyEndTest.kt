// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * What a request that fails before its body was sent leaves of that body. A request the library will not send again ends
 * its body with the failure, so an application writing it is released instead of waiting forever for a reader that never
 * comes; one refused before anything of it left (RequestNotProcessed.neverSent) leaves it unread, as that exception
 * promises, for the retry the Ktor engine makes with the same body.
 */
class RequestBodyEndTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun post(body: ByteChannel, headers: Http3Headers = Http3Headers.Empty) =
        http3Request("POST", "server.test", "/") {
            this.body = body
            this.headers = headers
        }

    /** [body] was ended by the library: closed for writing, and a write fails at once instead of waiting for a reader. */
    private suspend fun assertReleased(body: ByteChannel) {
        assertTrue(body.isClosedForWrite, "the body of the failed request is closed for writing")
        assertFailsWith<Throwable>("a write to the body of the failed request succeeded") {
            body.writeFully(ByteArray(1))
            body.flush()
        }
    }

    /** A request on a connection that already ended fails at once: its body ends with the connection's error. */
    @Test fun requestOnAnEndedConnectionReleasesItsBody() =
        h3Test {
            H3Pair.open().useScoped { p ->
                p.server.close()
                withTimeout(5.seconds) { p.client.closed.await() }
                val body = ByteChannel()
                val e = assertFailsWith<Throwable>("a request on an ended connection failed") { p.client.request(post(body)) }
                assertFalse(e is Http3Exception.RequestNotProcessed, "the connection's error, not a refusal: $e")
                assertReleased(body)
            }
        }

    /** A request the client refuses as malformed (RFC 9114 section 4.2) before it opens a stream: its body ends too. */
    @Test fun invalidRequestReleasesItsBody() =
        h3Test {
            H3Pair.open().useScoped { p ->
                val body = ByteChannel()
                assertFailsWith<IllegalArgumentException>("a field value with trailing whitespace was refused") {
                    p.client.request(post(body, Http3Headers.of("x-a" to "v ")))
                }
                assertReleased(body)
            }
        }

    /**
     * A request after the server's GOAWAY is never sent (RFC 9114 section 5.2): RequestNotProcessed with neverSent, and
     * its body stays open and unread, so the same body can go again on a new connection.
     */
    @Test fun requestRefusedByGoAwayKeepsItsBody() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch { runCatching { p.server.goAway() } }
                withTimeout(5.seconds) { p.client.goAwayReceived.filterNotNull().first() }
                val body = ByteChannel()
                val e = assertFailsWith<Http3Exception.RequestNotProcessed>("a request after GOAWAY was refused") { p.client.request(post(body)) }
                @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
                assertTrue(e.neverSent, "refused before anything went out")
                assertFalse(body.isClosedForWrite, "the body of a request never sent stays open for a retry")
                body.writeFully("again".encodeToByteArray())
                body.flushAndClose()
                assertContentEquals("again".encodeToByteArray(), body.readBuffer().readByteArray(), "the body is unread")
            }
        }
}
