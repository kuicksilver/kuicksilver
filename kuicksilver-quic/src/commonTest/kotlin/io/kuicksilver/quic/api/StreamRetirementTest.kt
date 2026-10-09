// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.ConnectionRuntime
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.seconds

/** Reset and stopped streams are retired: MAX_STREAMS credit returns, wrappers and tickers go. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class StreamRetirementTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun assertRetired(
        c: QuicConnection,
        s: QuicConnection,
    ) {
        val rt = c as ConnectionRuntime
        val srt = s as ConnectionRuntime
        withTimeoutOrNull(5.seconds) {
            while (rt.streamCountForTest > 0 || srt.streamCountForTest > 0 || rt.tickerCountForTest > 0 ||
                srt.tickerCountForTest > 0
            ) {
                delay(20)
            }
        }
        assertEquals(0, rt.streamCountForTest, "client wrappers ${rt.streamIdsForTest}")
        assertEquals(0, srt.streamCountForTest, "server wrappers ${srt.streamIdsForTest}")
        assertEquals(0, rt.tickerCountForTest)
        assertEquals(0, srt.tickerCountForTest)
    }

    private suspend fun expectReset(st: QuicStream) {
        val e = assertFailsWith<QuicException.StreamError.Reset> { st.input.readExactly(2) }
        assertEquals(st.id, e.streamId)
    }

    @Test fun peerResetStreamsReturnStreamCredit() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxBidiStreams = 10 }).use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    repeat(50) {
                        val st = c.openBidi()
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                        st.reset(7)
                        val ss = s.acceptStream()
                        expectReset(ss)
                        ss.reset(8) // the server's send half ends too
                        expectReset(st)
                    }
                    assertRetired(c, s)
                    assertNotNull(
                        withTimeoutOrNull(5.seconds) { c.openBidi() },
                        "the 51st stream opens: the reset streams returned their MAX_STREAMS credit",
                    )
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun stoppedStreamsAreRetiredWhenThePeerResets() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxBidiStreams = 10 }).use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    repeat(50) {
                        val st = c.openBidi()
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                        val ss = s.acceptStream()
                        ss.input.readExactly(1)
                        ss.input.cancel(null)
                        ss.reset(8) // STOP_SENDING: the client answers with RESET_STREAM
                        expectReset(st)
                    }
                    assertRetired(c, s)
                    assertNotNull(withTimeoutOrNull(5.seconds) { c.openBidi() }, "the 51st stream opens")
                    c.close()
                    s.close()
                }
            }
        }
}
