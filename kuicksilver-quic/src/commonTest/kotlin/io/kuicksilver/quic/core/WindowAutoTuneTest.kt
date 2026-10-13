// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.quicConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Receive-window auto-tuning (RFC 9000 section 4.2 leaves the strategy open; `RecvFlowController`, quic-go's rule): a window
 * grows only while the application reads a whole window in under four RTTs — faster than the window lets the peer send — and
 * stays at its initial size for a slow reader, so per-connection memory follows what the application consumes.
 */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class WindowAutoTuneTest {
    /** Uploads [size] bytes; the server reads up to [chunk] bytes every [readEvery]. Returns (stream window, connection window). */
    private fun upload(
        size: Int,
        chunk: Int,
        readEvery: Duration,
        serverQuic: QuicConfig = QuicConfig.Default,
    ): Pair<Long, Long> {
        val p = CorePair(serverQuic = serverQuic)
        try {
            assertTrue(p.handshake())
            p.runUntil(200.milliseconds) { false }
            val id = p.client.openStream(bidi = true, StreamPriority.Default)
            val data = ByteArray(65536)
            val buf = ByteArray(chunk)
            var written = 0L
            var read = 0L
            var nextRead = p.now
            var windows = -1L to -1L
            assertTrue(
                p.runUntil(120.seconds) {
                    while (written < size) {
                        val n = p.client.writeStream(id, data, 0, minOf(data.size.toLong(), size - written).toInt(), false)
                        if (n <= 0) break
                        written += n
                    }
                    val s = p.server!!
                    if (p.now >= nextRead) {
                        nextRead = p.now + readEvery
                        var got = 0
                        while (got < chunk) {
                            val n = s.readStream(id, buf, 0, chunk - got)
                            if (n <= 0) break
                            got += n
                        }
                        read += got
                        windows = s.streams.recvWindowForTest(id) to s.streams.connWindowForTest
                    }
                    read >= size
                },
                "delivered $read of $size",
            )
            return windows
        } finally {
            p.close()
        }
    }

    @Test fun slowReaderKeepsTheInitialWindow() {
        // 64 KiB every 100 ms against a 10 ms RTT: the window (512 KiB) takes 800 ms = 80 RTT, far beyond 4 RTT
        val (stream, conn) = upload(2 shl 20, 65536, 100.milliseconds)
        assertEquals(524_288L, stream, "stream window")
        assertTrue(conn <= 786_432L, "connection window $conn")
    }

    @Test fun fastReaderGrowsTheWindow() {
        // 16 KiB windows limit the transfer (a window goes by in well under 4 RTT): they grow
        val small =
            quicConfig {
                initialStreamWindow = 16_384
                initialConnectionWindow = 24_576
            }
        val (stream, conn) = upload(4 shl 20, 1 shl 20, Duration.ZERO, small)
        assertTrue(stream >= 4 * 16_384L, "stream window $stream")
        assertTrue(conn >= stream * 3 / 2 || conn == 15_728_640L, "connection window $conn follows the stream window")
    }
}
