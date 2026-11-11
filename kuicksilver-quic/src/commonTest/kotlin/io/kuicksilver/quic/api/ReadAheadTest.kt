// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.readAhead
import io.kuicksilver.quic.runtime.StreamRuntime
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * `QuicStream.readAhead` fixes a stream offset: reads in small pieces never take bytes from the transport past it, so
 * what lies beyond (HTTP/3: a QPACK field section that may block, RFC 9204 section 2.2.1) stays in the flow-control
 * window. A limit counted from each read's position instead moved on with every piece.
 */
class ReadAheadTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun readsInPiecesTakeNothingPastTheLimit() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val sent = ByteArray(30_000) { it.toByte() }
                    val out = c.openBidi()
                    out.output.writeFully(sent)
                    out.output.flushAndClose()
                    val st = s.acceptStream()
                    st.readAhead = 20_000
                    val got = ByteArray(sent.size)
                    var n = 0
                    while (n < 20_000) n += st.input.readAvailable(got, n, minOf(1_000, 20_000 - n))
                    assertEquals(20_000, (st as StreamRuntime).inputTakenForTest, "taken past the limit")
                    assertEquals(0, st.readAhead)
                    st.readAhead = Long.MAX_VALUE
                    while (true) {
                        val r = st.input.readAvailable(got, n, got.size - n)
                        if (r < 0) break
                        n += r
                    }
                    assertContentEquals(sent, got)
                    // a value that reaches past the largest offset means no limit (saturating, never a wrapped offset)
                    st.readAhead = Long.MAX_VALUE - 1
                    assertEquals(Long.MAX_VALUE, st.readAhead)
                    c.close()
                    s.close()
                }
            }
        }
}
