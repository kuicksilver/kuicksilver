// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, InternalKuicksilverApi::class)

package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.time.Duration.Companion.seconds

/**
 * The flood classes of RFC 9113 section 10.5 against the client engine, from a hostile server over TLS on a loopback
 * socket: once the request is in flight the server floods and reads nothing. PINGs (CVE-2019-9512), SETTINGS
 * (CVE-2019-9515), empty DATA frames (CVE-2019-9518), PRIORITY frames (CVE-2019-9513) and frames of an unknown type each
 * end the connection on our side with ENHANCE_YOUR_CALM, and the call fails with that code (the core's bounds:
 * core.FloodClassesTest); the server sees our GOAWAY when it reads afterwards, unless the TCP reset of its unread data
 * wins the race.
 */
class ClientH2FloodTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun frame(
        type: Int,
        flags: Int,
        stream: Int,
        payload: ByteArray = ByteArray(0),
    ): ByteArray =
        byteArrayOf(
            (payload.size shr 16).toByte(),
            (payload.size shr 8).toByte(),
            payload.size.toByte(),
            type.toByte(),
            flags.toByte(),
            (stream ushr 24).toByte(),
            (stream shr 16).toByte(),
            (stream shr 8).toByte(),
            stream.toByte(),
        ) + payload

    /** Reads one frame: its type, flags, stream and payload; null at the end of the input. */
    private suspend fun ByteReadChannel.frame(): Triple<Int, Int, ByteArray>? {
        val head = runCatching { readByteArray(9) }.getOrNull() ?: return null
        val len = ((head[0].toInt() and 0xff) shl 16) or ((head[1].toInt() and 0xff) shl 8) or (head[2].toInt() and 0xff)
        val payload = runCatching { readByteArray(len) }.getOrNull() ?: return null
        return Triple(head[3].toInt() and 0xff, head[4].toInt() and 0xff, payload)
    }

    /**
     * A server that sends its SETTINGS, waits for the request's HEADERS (stream 1), sends [before] (its response's start,
     * say), then [count] frames [flood] makes in batches without reading, and finally reads what is left and completes
     * [goAway] with the code of our GOAWAY, if it saw one.
     */
    private suspend fun flooded(
        count: Int,
        before: ByteArray = ByteArray(0),
        flood: (Int) -> ByteArray,
    ): Pair<Http2Exception.ConnectionClosed, Long?> {
        val goAway = CompletableDeferred<Long?>()
        var failure: Http2Exception.ConnectionClosed? = null
        tlsWithSilentUdp(listOf("h2"), silentUdp = false, handler = { _, _, input: ByteReadChannel, output: ByteWriteChannel ->
            try {
                input.readByteArray(24) // the client preface
                output.writeFully(frame(0x4, 0, 0))
                output.flush()
                while (true) {
                    val (type, _, _) = input.frame() ?: return@tlsWithSilentUdp
                    if (type == 0x1) break
                }
                output.writeFully(before)
                runCatching {
                    var i = 0
                    while (i < count) {
                        val batch = ArrayList<ByteArray>()
                        repeat(minOf(1_000, count - i)) { batch += flood(i++) }
                        for (b in batch) output.writeFully(b)
                        output.flush()
                    }
                }
                var code: Long? = null
                while (true) {
                    val (type, _, payload) = input.frame() ?: break
                    if (type == 0x7) {
                        code = ((payload[4].toLong() and 0xff) shl 24) or ((payload[5].toLong() and 0xff) shl 16) or
                            ((payload[6].toLong() and 0xff) shl 8) or (payload[7].toLong() and 0xff)
                    }
                }
                goAway.complete(code)
            } finally {
                goAway.complete(null)
            }
        }) { port ->
            testClient().use { c ->
                failure = assertFailsWith<Http2Exception.ConnectionClosed> { c.get("https://127.0.0.1:$port/") }
            }
        }
        return failure!! to withTimeout(30.seconds) { goAway.await() }
    }

    private fun assertCalm(r: Pair<Http2Exception.ConnectionClosed, Long?>) {
        val (e, seen) = r
        assertEquals(Http2ErrorCode.ENHANCE_YOUR_CALM, e.code, "$e")
        assertFalse(e.byPeer, "ended by the client: $e")
        seen?.let { assertEquals(0xbL, it, "the GOAWAY the server read") }
    }

    @Test fun negative_pingFloodFromTheServer() =
        clientTest {
            assertCalm(flooded(100_000) { frame(0x6, 0, 0, ByteArray(8) { b -> (it shr (8 * (b % 4))).toByte() }) })
        }

    @Test fun negative_settingsFloodFromTheServer() =
        clientTest {
            assertCalm(flooded(100_000) { frame(0x4, 0, 0, byteArrayOf(0, 4, 0, 0, 0, (it and 1).toByte())) })
        }

    @Test fun negative_emptyDataFloodFromTheServer() =
        clientTest {
            // the response's head first (:status 200), then DATA frames with nothing in them and no END_STREAM
            assertCalm(flooded(100_000, before = frame(0x1, 0x4, 1, byteArrayOf(0x88.toByte()))) { frame(0x0, 0, 1) })
        }

    @Test fun negative_priorityAndUnknownFloodFromTheServer() =
        clientTest {
            assertCalm(
                flooded(100_000) { frame(0x2, 0, 1 + 2 * (it % 100), byteArrayOf(0, 0, 0, (1 + 2 * ((it + 1) % 100)).toByte(), 15)) },
            )
            assertCalm(flooded(100_000) { frame(0xfa, 0, 0) })
        }
}
