// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class, ExperimentalCoroutinesApi::class)

package io.kuicksilver.http2.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.hpack.HpackEncoder
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Floods against the server runtime, where the engine (not the core) decides that a request is bad: RFC 9113 section
 * 8.1.1, "Malformed requests or responses that are detected MUST be treated as a stream error (Section 5.4.2) of type
 * PROTOCOL_ERROR". The client reads everything we write, so no queue fills up: only the glitch budget can end it.
 */
class H2ServerFloodTest {
    private class Client(
        val toServer: ByteChannel,
        val toClient: ByteChannel,
    ) {
        val hpack = HpackEncoder()
        private val dec = FrameDecoder(H2.MAX_MAX_FRAME_SIZE)
        private val buf = ByteArray(65_536)
        val frames = mutableListOf<Frame>()

        /** Frames that answer a request (RST_STREAM, a whole response) or end the connection (GOAWAY), counted as they are read. */
        val answers = MutableStateFlow(0)

        /** Reads what the server writes until it closes its output. */
        suspend fun readToEnd() {
            while (true) {
                val n = toClient.readAvailable(buf, 0, buf.size)
                if (n < 0) return
                var p = 0
                while (p < n) {
                    p += dec.feed(buf, p, n - p)
                    while (true) {
                        val f = dec.next() ?: break
                        frames += f
                        if (f is Frame.RstStream || (f is Frame.Headers && f.endStream)) answers.value++
                        if (f is Frame.GoAway) answers.value = Int.MAX_VALUE
                    }
                }
            }
        }
    }

    /** A server with no handler work to do (no request is valid), and a client flooding it with [request] while reading. */
    private suspend fun TestScope.flood(
        count: Int,
        batch: Int = 50,
        request: (Client, Int) -> ByteArray,
    ): Client {
        val toServer = ByteChannel()
        val toClient = ByteChannel()
        val server =
            H2ServerConnection.start(toServer, toClient, Http2Settings(), backgroundScope, {
                toServer.close()
                toClient.close()
            }, { testScheduler.currentTime * 1_000_000 })
        backgroundScope.launch { for (r in server.requests) r.release() }
        val c = Client(toServer, toClient)
        backgroundScope.launch {
            runCatching {
                toServer.writeFully(H2.PREFACE)
                toServer.writeFully(FrameEncoder.settings(IntArray(0), LongArray(0)))
                toServer.writeFully(FrameEncoder.settingsAck())
                var i = 0
                while (i < count) {
                    val frames = ArrayList<ByteArray>()
                    repeat(minOf(batch, count - i)) { frames += request(c, i++) }
                    for (b in frames) toServer.writeFully(b)
                    toServer.flush()
                    // a client that reads: the next batch goes once the server answered this one, so no queue of ours fills
                    c.answers.first { it >= i }
                }
                toServer.close() // done: the server sees the end of its input
            }
        }
        c.readToEnd()
        return c
    }

    private fun Client.calm(): Frame.GoAway? = frames.filterIsInstance<Frame.GoAway>().lastOrNull()

    /**
     * Requests without pseudo-header fields (a zero-length field block, CVE-2019-9516's empty headers) and requests with a
     * content-length but no content: each is malformed, and each reset is an error the client caused. They take from the
     * glitch budget as the core's own stream errors do (MadeYouReset, CVE-2025-8671), so the flood ends with
     * ENHANCE_YOUR_CALM after the budget of 10 000 even though the client reads every RST_STREAM.
     */
    @Test
    fun negative_malformedRequestFloodEndsCalm() =
        runTest {
            val empty = flood(30_000) { _, i -> FrameEncoder.headers(1 + 2 * i, ByteArray(0), endStream = true, endHeaders = true) }
            val g =
                assertNotNull(
                    empty.calm(),
                    "no GOAWAY after ${empty.frames.count {
                        it is Frame.RstStream
                    }} resets: ${empty.frames.filterIsInstance<Frame.RstStream>().groupingBy { it.errorCode }.eachCount()}",
                )
            assertTrue("glitches" in g.debug.decodeToString(), g.debug.decodeToString())
            assertEquals(Http2ErrorCode.ENHANCE_YOUR_CALM.code, g.errorCode, g.debug.decodeToString())
            val resets = empty.frames.count { it is Frame.RstStream }
            println("malformed request flood (empty field blocks): $resets resets before GOAWAY")
            assertTrue(resets in 9_900..10_001, "resets before GOAWAY: $resets")

            val length =
                flood(30_000) { c, i ->
                    val get =
                        listOf(
                            ":method" to "GET",
                            ":scheme" to "https",
                            ":authority" to "a.test",
                            ":path" to "/",
                            "content-length" to "5",
                        )
                    FrameEncoder.headers(1 + 2 * i, c.hpack.encode(get), endStream = true, endHeaders = true)
                }
            assertEquals(Http2ErrorCode.ENHANCE_YOUR_CALM.code, assertNotNull(length.calm()).errorCode)
        }

    /**
     * Requests past SETTINGS_MAX_CONCURRENT_STREAMS (100) in batches of 500, the next batch once all are answered: 400 are
     * refused each time, never more than 4 x the limit in a row since the 100 that ran finished in between. After our
     * SETTINGS were acknowledged each refusal is an error of the client's (RFC 9113 section 5.1.2), a glitch, so the flood
     * ends with ENHANCE_YOUR_CALM.
     */
    @Test
    fun negative_refusedRequestFloodEndsCalm() =
        runTest {
            val get = listOf(":method" to "GET", ":scheme" to "https", ":authority" to "a.test", ":path" to "/")
            val c =
                flood(
                    100_000,
                    batch = 500,
                ) { c, i -> FrameEncoder.headers(1 + 2 * i, c.hpack.encode(get), endStream = true, endHeaders = true) }
            val refused = c.frames.count { it is Frame.RstStream && it.errorCode == Http2ErrorCode.REFUSED_STREAM.code }
            println("refused request flood: $refused refused before GOAWAY")
            val g = assertNotNull(c.calm(), "no GOAWAY after $refused refused")
            assertEquals(Http2ErrorCode.ENHANCE_YOUR_CALM.code, g.errorCode, g.debug.decodeToString())
            assertTrue(refused in 9_000..10_001, "refused before GOAWAY: $refused")
        }
}
