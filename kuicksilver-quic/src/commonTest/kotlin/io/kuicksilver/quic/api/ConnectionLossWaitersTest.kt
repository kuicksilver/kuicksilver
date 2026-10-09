// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.ClosedWriteChannelException
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.time.Duration.Companion.seconds

/** Coroutines suspended inside the runtime learn the connection's own reason when it closes. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ConnectionLossWaitersTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun waitersSeeTheConnectionsReason() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { maxBidiStreams = 1 }).use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    val first = c.openBidi()
                    val writer =
                        async {
                            runCatching {
                                val chunk = ByteArray(64 * 1024)
                                while (true) first.output.writeFully(chunk, 0, chunk.size)
                            }.exceptionOrNull()
                        } // the server never reads: the writer ends up waiting for ACKs
                    val opener = async { runCatching { c.openBidi() }.exceptionOrNull() } // waits for MAX_STREAMS
                    delay(500)
                    assertFalse(writer.isCompleted, "the writer is blocked")
                    assertFalse(opener.isCompleted, "openBidi is blocked")
                    c.close(5, "bye")
                    val o = opener.await()
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(o, "openBidi: $o")
                    assertEquals(5L, o.code)
                    val w = writer.await()
                    assertIs<ClosedWriteChannelException>(w, "writer: $w")
                    val cause =
                        generateSequence(w.cause) {
                            it.cause
                        }.firstOrNull {
                            it !is ClosedWriteChannelException
                        } // stack-trace recovery (debug mode) may wrap a copy of the channel exception around the original
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(cause, "writer cause: $cause")
                    assertEquals(5L, cause.code)
                    s.close()
                }
            }
        }
}
