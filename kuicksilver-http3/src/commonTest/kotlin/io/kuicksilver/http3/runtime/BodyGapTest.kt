// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.qpack.entrySize
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.async
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals

/** A request body that matches its declared length exactly. */
class BodyGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * RFC 9114 section 4.1.2: "A request or response that is defined as having content when it contains a Content-Length
     * header field ... is malformed if the value of the Content-Length header field does not equal the sum of the DATA frame
     * lengths received." A body of exactly the declared length is the ordinary case: every byte goes out and arrives,
     * written in one piece or in several.
     */
    @Test fun negative_bodyOfExactlyTheDeclaredLengthIsSent() =
        h3Test {
            H3Pair.open().use { p ->
                for (body in listOf("hello", "x".repeat(70_000))) {
                    val got =
                        async {
                            val r = p.server.acceptRequest()
                            r.body
                                .readAllBytes()
                                .decodeToString()
                                .also { r.respond(200).finish() }
                        }
                    val resp =
                        p.client.request(
                            http3Request("POST", "server.test", "/") {
                                headers = Http3Headers.of("content-length" to body.length.toString())
                                this.body = ByteReadChannel(body.encodeToByteArray())
                            },
                        )
                    assertEquals(body, got.await())
                    assertEquals(200, resp.status)
                }
            }
        }

    /** The same rule for a response: a body of exactly its content-length arrives whole. */
    @Test fun negative_responseBodyOfExactlyTheDeclaredLengthIsSent() =
        h3Test {
            H3Pair.open().use { p ->
                for (body in listOf("hello", "x".repeat(70_000))) {
                    val served =
                        async {
                            val w = p.server.acceptRequest().respond(200, Http3Headers.of("content-length" to body.length.toString()))
                            w.output.writeFully(body.encodeToByteArray())
                            w.finish()
                        }
                    val resp = p.client.request(get())
                    assertEquals(body, resp.body.readAllBytes().decodeToString())
                    served.await()
                }
            }
        }

    /**
     * RFC 9110 section 15.4.5: "A 304 response is terminated by the end of the header section; it cannot contain content or
     * trailers." What the application writes for one is dropped, never sent: the client reads an empty body.
     */
    @Test fun negative_a304ResponseCarriesNoContent() =
        h3Test {
            H3Pair.open().use { p ->
                val served =
                    async {
                        val w = p.server.acceptRequest().respond(304)
                        w.output.writeFully("not for a 304".encodeToByteArray())
                        w.finish()
                    }
                val resp = p.client.request(get())
                assertEquals(304, resp.status)
                assertEquals(0, resp.body.readAllBytes().size)
                served.await()
            }
        }

    /**
     * RFC 9110 section 15.2: "A client MUST be able to parse one or more 1xx responses received prior to a final response";
     * the client bounds them together by its SETTINGS_MAX_FIELD_SECTION_SIZE (RFC 9114 section 4.2.2 sizes). Interim
     * sections that add up to exactly that limit are within it.
     */
    @Test fun negative_interimResponsesExactlyAtTheLimitAreRead() =
        h3Test {
            val perInterim = entrySize(":status", "103") + entrySize("link", "x".repeat(100))
            H3Pair.open(clientSettings = http3Settings { maxFieldSectionSize = 2 * perInterim }).use { p ->
                val served =
                    async {
                        val r = p.server.acceptRequest()
                        repeat(2) { r.sendInformational(103, Http3Headers.of("link" to "x".repeat(100))) }
                        r.respond(200).finish()
                    }
                var seen = 0
                val resp = p.client.request(http3Request("GET", "server.test", "/") { onInformational = { _, _ -> seen++ } })
                assertEquals(200, resp.status)
                assertEquals(2, seen)
                served.await()
            }
        }
}
