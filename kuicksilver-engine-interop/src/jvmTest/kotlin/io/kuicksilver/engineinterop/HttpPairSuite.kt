// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.client.plugins.timeout
import io.ktor.client.request.get
import io.ktor.client.request.head
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.prepareGet
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsBytes
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpProtocolVersion
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.security.MessageDigest
import java.util.UUID
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * HTTP semantics between one Ktor client engine and one Ktor server engine, at least one of them Kuicksilver's, over one
 * wire protocol (cleartext HTTP/1.1, HTTP/1.1 or HTTP/2 over TLS, HTTP/3). Each subclass is one pair; every test asserts
 * what RFC 9110 (semantics), RFC 9112 (HTTP/1.1), RFC 9113 (HTTP/2) or RFC 9114 (HTTP/3) require of both ends.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
internal abstract class HttpPairSuite(
    private val serverEngine: ServerEngine,
    private val clientEngine: ClientEngine,
    private val wire: Wire,
) {
    enum class Wire(
        val version: HttpProtocolVersion,
    ) {
        H1Clear(HttpProtocolVersion.HTTP_1_1),
        H1Tls(HttpProtocolVersion.HTTP_1_1),
        H2(HttpProtocolVersion.HTTP_2_0),
        H3(HttpProtocolVersion.HTTP_3_0),
    }

    protected lateinit var server: RunningServer
    protected lateinit var client: HttpClient

    protected open fun start(): RunningServer =
        startServer(serverEngine, tls = wire != Wire.H1Clear, http2 = wire == Wire.H2, http3 = wire == Wire.H3)

    protected open fun newClient(): HttpClient = ktorClient(clientEngine, http2 = wire == Wire.H2, h3Only = wire == Wire.H3)

    @BeforeAll fun startPair() {
        server = start()
        client = newClient()
    }

    @AfterAll fun stopPair() {
        client.close()
        server.close()
    }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    /** The protocol ALPN (or the scheme) chose is the one this pair is about: HTTP/2 needs `h2` from both ends (RFC 9113 section 3.2). */
    @Test fun protocolIsNegotiated() =
        interopTest {
            val r = client.get(server.url("/hello"))
            assertEquals(HttpStatusCode.OK, r.status)
            assertEquals("hello", r.bodyAsText())
            assertEquals(wire.version, r.version, "the protocol of the response")
        }

    @Test fun postEmptyBody() =
        interopTest {
            val r = client.post(server.url("/echo")) { setBody(ByteArray(0)) }
            assertEquals(HttpStatusCode.OK, r.status)
            assertEquals("0", r.headers["x-received-length"])
            assertEquals(0, r.bodyAsBytes().size)
        }

    @Test fun postSmallBody() =
        interopTest {
            val r = client.post(server.url("/echo")) { setBody("small body".encodeToByteArray()) }
            assertEquals("small body", r.bodyAsText())
        }

    /** A 1 MiB body each way, with its length known up front (Content-Length over HTTP/1.1). */
    @Test fun post1MiB() =
        interopTest {
            val body = Random(1).nextBytes(1 shl 20)
            val r = client.post(server.url("/echo")) { setBody(body) }
            assertEquals((1 shl 20).toString(), r.headers["x-received-length"])
            assertContentEquals(sha256(body), sha256(r.bodyAsBytes()))
        }

    /** A request body of unknown length, written in pieces (chunked over HTTP/1.1, RFC 9112 section 7.1). */
    @Test fun postStreamingBody() =
        interopTest {
            val body = Random(2).nextBytes(256 * 1024)
            val r =
                client.post(server.url("/echo")) {
                    setBody(
                        object : OutgoingContent.WriteChannelContent() {
                            override suspend fun writeTo(channel: ByteWriteChannel) {
                                for (off in body.indices step 4096) {
                                    channel.writeFully(body, off, off + 4096)
                                    channel.flush()
                                }
                            }
                        },
                    )
                }
            assertEquals(body.size.toString(), r.headers["x-received-length"])
            assertContentEquals(sha256(body), sha256(r.bodyAsBytes()))
        }

    /** A response of unknown length written in 4 KiB pieces. */
    @Test fun streamingResponse() =
        interopTest {
            val r = client.get(server.url("/chunked/300000"))
            assertEquals(HttpStatusCode.OK, r.status)
            assertContentEquals(pattern(300_000), r.bodyAsBytes())
        }

    /** A response with Content-Length: the body is exactly that long. */
    @Test fun fixedLengthResponse() =
        interopTest {
            val r = client.get(server.url("/bytes/100000"))
            assertEquals("100000", r.headers[HttpHeaders.ContentLength])
            assertContentEquals(pattern(100_000), r.bodyAsBytes())
        }

    /**
     * 50 request fields and one of 2 KiB reach the application, and 100 response fields reach the client; the request's
     * field section stays below 8 KiB as RFC 9113 section 6.5.2 counts it (32 octets per field line on top), the limit
     * Netty announces. Field values keep their inner spaces, quotes, commas and semicolons, and lose the optional
     * whitespace around them (RFC 9110 section 5.5: "a field value does not include leading or trailing whitespace").
     */
    @Test fun manyAndLargeHeaders() =
        interopTest {
            val big = "b".repeat(2048)
            val r =
                client.get(server.url("/headers")) {
                    repeat(50) { header("x-h-%03d".format(it), "v$it") }
                    header("x-big", big)
                    header("x-punct", "a \"quoted, value\"; q=0.5, b")
                    header("x-ows", "  padded value\t ")
                }
            val lines = r.bodyAsText().lines()
            assertEquals(53, lines.size, "the request fields the application saw: $lines")
            assertTrue("x-big: $big" in lines)
            assertTrue("x-punct: a \"quoted, value\"; q=0.5, b" in lines, "$lines")
            assertTrue("x-ows: padded value" in lines, "$lines")
            assertTrue("x-h-049: v49" in lines)
            val many = client.get(server.url("/many-headers?n=100&size=40"))
            assertEquals(100, many.headers.names().count { it.lowercase().startsWith("x-r-") })
            assertEquals("v".repeat(40), many.headers["x-r-042"])
        }

    /** UTF-8 in the target, percent-encoded (RFC 3986 section 2.1), arrives decoded in path and query alike. */
    @Test fun percentEncodedUtf8Target() =
        interopTest {
            val r = client.get(server.url("/utf8/%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82?q=%E2%9C%93%20ok"))
            assertEquals("привет|✓ ok", r.bodyAsText())
        }

    /** RFC 9110 section 15.3.5: a 204 response cannot contain content; section 15.5.5: 404 can. */
    @Test fun statusCodes() =
        interopTest {
            val noContent = client.get(server.url("/status/204"))
            assertEquals(HttpStatusCode.NoContent, noContent.status)
            assertEquals(0, noContent.bodyAsBytes().size)
            for (code in listOf(200, 201, 400, 404, 418, 500, 503)) {
                val r = client.get(server.url("/status/$code"))
                assertEquals(code, r.status.value)
                assertEquals("status $code", r.bodyAsText())
            }
            // the connection is still usable after a 204 that had no body to delimit
            assertEquals("hello", client.get(server.url("/hello")).bodyAsText())
        }

    /**
     * RFC 9110 section 9.3.2: a HEAD response is a GET response without content, and its Content-Length is the one the
     * GET would have had (section 8.6). The next request on the connection is not confused by the missing body.
     */
    @Test fun headHasNoContent() =
        interopTest {
            val r = client.head(server.url("/bytes/1000"))
            assertEquals(HttpStatusCode.OK, r.status)
            assertEquals("1000", r.headers[HttpHeaders.ContentLength])
            assertEquals(0, r.bodyAsBytes().size)
            assertContentEquals(pattern(1000), client.get(server.url("/bytes/1000")).bodyAsBytes())
        }

    /**
     * RFC 9110 section 13.1.2 and 15.4.5: a matching If-None-Match gets 304 without content, with the ETag a 200 would
     * have carried; the connection then carries the next request.
     */
    @Test fun conditionalGetIs304() =
        interopTest {
            val first = client.get(server.url("/etag"))
            assertEquals("\"v1\"", first.headers[HttpHeaders.ETag])
            val r = client.get(server.url("/etag")) { header(HttpHeaders.IfNoneMatch, "\"v1\"") }
            assertEquals(HttpStatusCode.NotModified, r.status)
            assertEquals("\"v1\"", r.headers[HttpHeaders.ETag])
            assertEquals(0, r.bodyAsBytes().size)
            assertEquals("hello", client.get(server.url("/hello")).bodyAsText())
        }

    /**
     * `Expect: 100-continue` with a body (RFC 9110 section 10.1.1): the server answers 100 or the final status, the
     * client sends the body, and the echo is complete. HTTP/2 and HTTP/3 carry the same field.
     */
    @Test fun expectContinue() =
        interopTest {
            val body = Random(3).nextBytes(64 * 1024)
            val r =
                client.post(server.url("/echo")) {
                    header(HttpHeaders.Expect, "100-continue")
                    setBody(body)
                }
            assertEquals(HttpStatusCode.OK, r.status)
            assertContentEquals(body, r.bodyAsBytes())
        }

    /**
     * Sequential requests reuse one connection (HTTP/1.1 persistence, RFC 9112 section 9.3; one HTTP/2 or HTTP/3
     * connection per origin): the server sees the same client port every time.
     */
    @Test open fun connectionReuse() =
        interopTest {
            val peers = (1..5).map { client.get(server.url("/peer")).bodyAsText() }.toSet()
            assertEquals(1, peers.size, "the client ports the server saw: $peers")
        }

    /** 32 requests at once: streams of one connection over HTTP/2 and HTTP/3, pooled connections over HTTP/1.1. */
    @Test fun concurrentRequests() =
        interopTest {
            val all =
                coroutineScope {
                    (0 until 32).map { i -> async { client.get(server.url("/bytes/${1000 + i}")).bodyAsBytes().size } }.awaitAll()
                }
            assertEquals((0 until 32).map { 1000 + it }, all)
        }

    /**
     * The client abandons a response mid-body (RFC 9113 section 8.7, RFC 9114 section 4.1.1: a stream reset; HTTP/1.1: the
     * connection closes, RFC 9112 section 9.6): the server's write fails instead of running to the end, and the client's
     * next request works.
     */
    @Test open fun cancelMidBody() =
        interopTest {
            val id = UUID.randomUUID().toString()
            val hold = server.probe.hold(id)
            client.prepareGet(server.url("/endless/$id")).execute { r ->
                val ch = r.bodyAsChannel()
                val buf = ByteArray(64 * 1024)
                var read = 0
                while (read < 256 * 1024) {
                    val n = ch.readAvailable(buf, 0, buf.size)
                    check(n > 0) { "the endless body ended after $read bytes" }
                    read += n
                }
            }
            val cause = withTimeout(20.seconds) { hold.aborted.await() }
            assertTrue(cause !is WrittenToTheEnd, "the server wrote the whole response")
            assertEquals("hello", client.get(server.url("/hello")).bodyAsText())
        }

    /**
     * A request timeout while the body is still arriving fails the call with Ktor's HttpRequestTimeoutException, the
     * server's write side sees the abort once released, and the client goes on.
     */
    @Test fun requestTimeoutMidBody() =
        interopTest {
            val id = UUID.randomUUID().toString()
            val hold = server.probe.hold(id)
            assertFailsWith<HttpRequestTimeoutException> {
                client.get(server.url("/hold/$id")) { timeout { requestTimeoutMillis = 1_000 } }.bodyAsText()
            }
            assertTrue(hold.entered.isCompleted, "the handler started")
            hold.release.complete(Unit)
            assertEquals("hello", client.get(server.url("/hello")).bodyAsText())
        }

    /**
     * Graceful stop with a request in flight (RFC 9113 section 6.8 and RFC 9114 section 5.2: GOAWAY lets streams already
     * accepted complete; HTTP/1.1: the response in progress completes, RFC 9112 section 9.6): the held response is
     * released only once the server is stopping, and the client receives all of it.
     */
    @Test open fun gracefulStopCompletesTheRequestInFlight() =
        interopTest {
            val s = start()
            val c = newClient()
            try {
                assertEquals("hello", c.get(s.url("/hello")).bodyAsText())
                val id = UUID.randomUUID().toString()
                val hold = s.probe.hold(id)
                coroutineScope {
                    val call = async { c.get(s.url("/hold/$id")).bodyAsText() }
                    hold.entered.await()
                    // Ktor's Netty and CIO engines wait out the whole grace period (Netty's quiet period): a short one
                    val stop = launch { s.stop(3_000, 6_000) }
                    s.probe.stopping.await()
                    hold.release.complete(Unit)
                    assertEquals("first;second", call.await())
                    stop.join()
                }
                val after = runCatching { c.get(s.url("/hello")) }
                assertTrue(after.isFailure, "a request after the stop got ${after.getOrNull()?.status}")
            } finally {
                c.close()
                s.close()
            }
        }

    /** A server whose certificate does not chain to the client's anchors is refused: the call fails, no response. */
    @Test fun negative_untrustedServerIsRefused() =
        interopTest {
            if (wire == Wire.H1Clear) return@interopTest
            val c = ktorClient(clientEngine, http2 = wire == Wire.H2, h3Only = wire == Wire.H3, otherCa = true)
            try {
                val r = runCatching { c.get(server.url("/hello")) }
                assertNotNull(r.exceptionOrNull(), "got ${r.getOrNull()?.status} from a server the client does not trust")
            } finally {
                c.close()
            }
        }
}
