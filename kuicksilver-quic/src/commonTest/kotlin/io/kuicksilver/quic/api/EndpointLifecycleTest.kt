// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.EndpointLoop
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** Endpoint-level lifecycle of the runtime. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class EndpointLifecycleTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun closeAndJoinReturnsOnceTheSocketIsClosed() =
        runBlocking {
            val p = ApiPair.open()
            withTimeout(30.seconds) {
                // close() is asynchronous (CONNECTION_CLOSE and the socket close happen on the loop); closeAndJoin() waits for them (K4 feedback E8)
                val (c, s) = p.connect()
                p.client.closeAndJoin()
                assertTrue(p.clientIo.closed, "the socket is closed when closeAndJoin returns")
                assertTrue(c.closed.isCompleted, "and so is the connection")
                assertFailsWith<QuicException.EndpointClosing> {
                    p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                }
                p.server.closeAndJoin()
                assertTrue(s.closed.isCompleted)
            }
        }

    @Test fun cancelledConnectClosesTheConnection() =
        runBlocking {
            ApiPair.open(serverAnswers = false).use { p ->
                withTimeout(30.seconds) {
                    // a cancelled connect leaves nothing behind; the connection closes (one closing period, 3 PTO) instead of retrying until the handshake timeout
                    val loop = p.client as EndpointLoop
                    val job = launch { p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build()) }
                    delay(200)
                    assertEquals(1, loop.core.connectionCount)
                    job.cancel()
                    job.join()
                    withTimeoutOrNull(5.seconds) { while (loop.core.connectionCount > 0) delay(20) }
                    assertEquals(0, loop.core.connectionCount, "the cancelled connection was retired")
                }
            }
        }

    @Test fun connectCancelledRightAfterAdoptionClosesTheConnection() =
        runBlocking {
            ApiPair.open(serverAnswers = false).use { p ->
                withTimeout(30.seconds) {
                    // cancellation at the withContext exit (after the loop adopted the connection) must not lose it either
                    val loop = p.client as EndpointLoop
                    repeat(5) {
                        val job =
                            launch(start = CoroutineStart.UNDISPATCHED) {
                                p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                            }
                        job.cancel()
                        job.join()
                    }
                    withTimeoutOrNull(5.seconds) { while (loop.core.connectionCount > 0) delay(20) }
                    assertEquals(0, loop.core.connectionCount, "no cancelled connection was kept")
                }
            }
        }

    @Test fun acceptAfterCloseThrowsEvenWithQueuedConnections() =
        runBlocking {
            val p = ApiPair.open()
            withTimeout(30.seconds) {
                // close() makes accept() throw from then on, also when handshaken connections were still waiting in the queue
                p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                delay(200) // the server side is queued, never accepted
                p.server.close()
                assertFailsWith<QuicException.EndpointClosing> { p.server.accept() }
                p.client.close()
            }
        }

    @Test fun payloadSizeAboveTheRuntimeSlotIsRefused() =
        runBlocking {
            // the loop's datagram slots hold 1500 bytes; advertising more would let peers send datagrams the runtime truncates
            assertFailsWith<IllegalArgumentException> { ApiPair.open(serverQuic = quicConfig { maxUdpPayloadSize = 9000 }) }
            ApiPair.open().use { p ->
                assertFailsWith<IllegalArgumentException> {
                    p.client.connect(
                        p.server.localAddress,
                        QuicClientConfig
                            .Builder(CoreFixtures.client())
                            .apply {
                                quic =
                                    quicConfig { maxUdpPayloadSize = 9000 }
                            }.build(),
                    )
                }
                assertEquals(0, (p.client as EndpointLoop).core.connectionCount)
            }
        }
}
