// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.http3Request
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
}
