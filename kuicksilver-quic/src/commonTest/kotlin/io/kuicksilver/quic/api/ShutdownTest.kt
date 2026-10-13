// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TransportError
import io.kuicksilver.quic.runtime.EndpointLoop
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/** `QuicEndpoint.shutdown(grace)`: no new connections, the live ones finish, the deadline holds. */
@OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.DelicateKuicksilverApi::class)
class ShutdownTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val clientConfig = QuicClientConfig.Builder(CoreFixtures.client()).build()

    private suspend fun shuttingDown(e: QuicEndpoint) {
        withTimeout(5.seconds) { while (!(e as EndpointLoop).core.shuttingDown) delay(5) }
    }

    @Test fun anInFlightTransferCompletesDuringTheGracePeriod(): Unit =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (client, server) = p.connect()
                    val payload = ByteArray(512 * 1024) { (it * 7).toByte() }
                    val firstBytes = CompletableDeferred<Unit>()
                    val received =
                        async {
                            val s = server.acceptStream()
                            val b = ByteArray(16 * 1024)
                            var total = 0
                            while (true) {
                                val n = s.input.readAvailable(b, 0, b.size)
                                if (n < 0) break
                                total += n
                                firstBytes.complete(Unit)
                            }
                            s.output.writeFully(total.toString().encodeToByteArray())
                            s.output.flushAndClose()
                            total
                        }
                    val s = client.openBidi()
                    val sending =
                        async {
                            s.output.writeFully(payload)
                            s.output.flushAndClose()
                        }
                    firstBytes.await()
                    val started = TimeSource.Monotonic.markNow()
                    val shutdown = async { p.server.shutdown(20.seconds) }
                    sending.await()
                    assertEquals(payload.size, received.await(), "the transfer finished after the shutdown began")
                    val b = ByteArray(32)
                    val n = s.input.readAvailable(b, 0, b.size)
                    assertEquals(payload.size.toString(), b.decodeToString(0, n))
                    client.close(0, "done") // the application ends its connection: nothing is left to wait for
                    shutdown.await()
                    assertTrue(started.elapsedNow() < 10.seconds, "shutdown returned once the last connection closed")
                    assertEquals(0, p.server.stats.connectionsActive)
                    assertEquals(0, p.server.stats.connectionsRefusedShutdown)
                }
            }
        }

    @Test fun aNewClientIsRefusedPromptly(): Unit =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (client, _) = p.connect() // keeps the endpoint in its grace period
                    val shutdown = async { p.server.shutdown(20.seconds) }
                    shuttingDown(p.server)
                    val other = p.net.open(InetSocketAddress("10.0.0.9", 9999))
                    val late =
                        QuicEndpoint.bind(
                            other.localAddress,
                            QuicEndpointConfig
                                .Builder()
                                .apply {
                                    crypto = NullCryptoProvider
                                    io =
                                        { other }
                                }.build(),
                        )
                    try {
                        val started = TimeSource.Monotonic.markNow()
                        val lost =
                            assertFailsWith<QuicException.ConnectionLost.TransportClosed> {
                                late.connect(
                                    p.server.localAddress,
                                    clientConfig,
                                )
                            }
                        assertEquals(TransportError.CONNECTION_REFUSED, lost.code)
                        assertTrue(started.elapsedNow() < 2.seconds, "refused at the Initial, not at a handshake timeout")
                        assertEquals(1, p.server.stats.connectionsRefusedShutdown)
                        assertEquals(1, p.server.stats.connectionsActive, "the live connection is untouched")
                    } finally {
                        late.close()
                    }
                    assertFailsWith<QuicException.EndpointClosing> { p.server.connect(p.client.localAddress, clientConfig) }
                    client.close(0, "done")
                    shutdown.await()
                }
            }
        }

    @Test fun theDeadlineClosesWhatIsLeft(): Unit =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (client, _) = p.connect() // never closed by the application
                    val started = TimeSource.Monotonic.markNow()
                    p.server.shutdown(300.milliseconds, code = 0x100, reason = "going away")
                    val took = started.elapsedNow()
                    assertTrue(took >= 300.milliseconds && took < 5.seconds, "the grace period, then the close: $took")
                    val reason = assertIs<QuicException.ConnectionLost.ApplicationClosed>(client.closed.await())
                    assertEquals(0x100, reason.code)
                    assertEquals("going away", reason.reason)
                    assertFailsWith<QuicException.EndpointClosing> { p.server.accept() }
                }
            }
        }

    @Test fun anIdleEndpointShutsDownAtOnce(): Unit =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(10.seconds) {
                    val started = TimeSource.Monotonic.markNow()
                    p.server.shutdown(20.seconds)
                    assertTrue(started.elapsedNow() < 5.seconds)
                }
            }
        }
}
