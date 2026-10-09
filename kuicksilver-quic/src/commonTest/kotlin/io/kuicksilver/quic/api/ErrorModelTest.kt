// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class ErrorModelTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun connectionCloseFailsStreamsWithSameReason() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush()
                    val ss = s.acceptStream()
                    ss.input.readExactly(1)
                    s.close(5, "server done")
                    val reason = c.closed.await()
                    val e = assertFailsWith<Throwable> { st.input.readExactly(1) }
                    assertTrue(
                        generateSequence<Throwable>(e) { it.cause }.any {
                            it is QuicException.ConnectionLost.ApplicationClosed &&
                                it.code == 5L &&
                                it.initiator == Initiator.Peer
                        },
                        "stream failure carries the connection's reason: $e",
                    )
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(reason)
                    assertEquals(5L, reason.code)
                }
            }
        }

    @Test fun cancellationNeverWrapped() =
        runBlocking {
            ApiPair.open(serverAnswers = false).use { p ->
                val scope = CoroutineScope(Job())
                val d = scope.async { p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                kotlinx.coroutines.delay(200)
                scope.cancel("stop")
                val e = assertFailsWith<Throwable> { d.await() }
                assertIs<CancellationException>(e)
                assertTrue(generateSequence<Throwable>(e) { it.cause }.none { it is QuicException })
            }
        }

    @Test fun peerTransportErrorSurfaces() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    c.core.testInjectHandshakeDone = true
                    val st = c.openBidi()
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    } // the write may already see the close
                    val r = c.closed.await()
                    assertIs<QuicException.ConnectionLost.TransportClosed>(r)
                    assertEquals(0x0aL, r.code)
                    assertEquals(Initiator.Peer, r.initiator)
                }
            }
        }
}
