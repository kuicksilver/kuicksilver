// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

import com.code_intelligence.jazzer.junit.FuzzTest
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.H2ConnectionError
import io.kuicksilver.http2.frame.H2StreamError
import io.kuicksilver.http2.hpack.HpackDecoder
import io.kuicksilver.http2.hpack.HpackError
import kotlin.test.assertTrue

/**
 * Fuzz target `frames`: input = [split byte][frames]. The bytes go into a FrameDecoder with a 16 KiB SETTINGS_MAX_FRAME_SIZE
 * in pieces of 1 + (split byte) bytes; only the decoder's own errors may escape, no payload is larger than the limit and
 * the decoder never allocates more than the input it was given plus one frame of at most the limit (a frame's buffer is
 * sized from its checked length when its header arrives).
 */
class H2FrameFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun frames(data: ByteArray) {
        if (data.isEmpty()) return
        val piece = 1 + (data[0].toInt() and 0xff)
        val d = FrameDecoder(16_384)
        var p = 1
        try {
            while (p < data.size) {
                val n = minOf(piece, data.size - p)
                var used = 0
                while (used < n) {
                    used += d.feed(data, p + used, n - used)
                    val f =
                        try {
                            d.next()
                        } catch (_: H2StreamError) {
                            null
                        }
                    when (f) {
                        is Frame.Data -> {
                            assertTrue(f.data.size <= 16_384 && f.flowLength <= 16_384)
                        }

                        is Frame.Headers -> {
                            assertTrue(f.fragment.size <= 16_384)
                        }

                        is Frame.Continuation -> {
                            assertTrue(f.fragment.size <= 16_384)
                        }

                        is Frame.Settings -> {
                            assertTrue(f.ids.size == f.values.size)
                        }

                        else -> {}
                    }
                }
                p += n
            }
        } catch (_: H2ConnectionError) {
        }
        assertTrue(d.allocatedBytes <= data.size + 16_384, "allocated ${d.allocatedBytes} for ${data.size} input bytes")
    }
}

/**
 * Fuzz target `hpackDecode`: input = [settings byte][block length, 2 bytes][block 1][block 2]. Two field blocks through one
 * decoder (the dynamic table carries over); the low bits of the first byte pick the table size and the list limit. Only
 * HpackError may escape; the fields that reach the sink never pass the list limit, and literals never allocate more than
 * the block's length times 8/5 (the densest Huffman code).
 */
class HpackDecodeFuzzTest {
    @FuzzTest(maxDuration = "60s")
    fun hpackDecode(data: ByteArray) {
        if (data.size < 3) return
        val table = intArrayOf(0, 256, 4_096, 65_536)[data[0].toInt() and 3]
        val limit = intArrayOf(64, 1_024, 16_384, 65_536)[(data[0].toInt() shr 2) and 3]
        val d = HpackDecoder(maxTableSize = table, maxHeaderListSize = limit)
        val split = minOf(((data[1].toInt() and 0xff) shl 8) or (data[2].toInt() and 0xff), data.size - 3)
        try {
            for ((off, len) in listOf(3 to split, 3 + split to data.size - 3 - split)) {
                var listSize = 0L
                d.decode(data, off, len) { n, v -> listSize += n.length + v.length + 32 }
                assertTrue(listSize <= limit, "list of $listSize above $limit")
                assertTrue(d.lastAllocated <= len.toLong() * 8 / 5 + 8, "allocated ${d.lastAllocated} for a block of $len")
            }
        } catch (_: HpackError) {
        }
    }
}
