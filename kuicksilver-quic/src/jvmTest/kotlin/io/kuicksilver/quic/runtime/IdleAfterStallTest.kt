// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeByte
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * RFC 9000 section 10.1: the idle timer restarts "when a packet from its peer is received and processed successfully". A
 * loop held up past a connection's idle deadline (a long GC pause, a stopped VM, a loaded host) holds both its timer
 * coroutine and the peer's datagram that arrived before the deadline; the datagram is processed first, as quic-go handles
 * its queued packets before its timers, so a connection whose peer spoke in time is not closed as idle.
 *
 * The stall is made on the client loop's own thread: the timer coroutine is woken first (it is queued ahead of what comes
 * next), the server then sends, and the thread stays busy until the idle deadline passed.
 */
class IdleAfterStallTest {
    private val serverAddr = InetSocketAddress("10.0.0.2", 2222)
    private val clientAddr = InetSocketAddress("10.0.0.1", 1111)

    @Volatile private var serverSent = false

    /** The server's datagrams are lost on the way to the client (its idle deadline then stops moving). */
    @Volatile private var dropToClient = false

    @Test fun negative_aPeerPacketQueuedBeforeTheIdleDeadlineKeepsTheConnection(): Unit =
        runBlocking {
            val idle = 1.seconds
            val net = MemoryNetwork()
            net.lose = { from, _, _ ->
                if (from == serverAddr) serverSent = true
                from == serverAddr && dropToClient
            }
            val sio = net.open(serverAddr)
            val cio = net.open(clientAddr)
            val server =
                QuicEndpoint.bind(
                    serverAddr,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig
                                    .Builder(CoreFixtures.server())
                                    .apply { quic = quicConfig { maxIdleTimeout = idle } }
                                    .build()
                            runtime { crypto = NullCryptoProvider }
                            runtime { io = { sio } }
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    clientAddr,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            runtime { crypto = NullCryptoProvider }
                            runtime { io = { cio } }
                        }.build(),
                ) as EndpointLoop
            val side = CoroutineScope(Dispatchers.Default + SupervisorJob())
            try {
                val (c, s) =
                    withTimeout(20.seconds) {
                        val accepted = async { server.accept() }
                        val c =
                            client.connect(
                                serverAddr,
                                QuicClientConfig
                                    .Builder(CoreFixtures.client())
                                    .apply { quic = quicConfig { maxIdleTimeout = idle } }
                                    .build(),
                            )
                        c to accepted.await()
                    }
                val stream = s.openUni()
                // the client's idle deadline is fixed first: the server's datagrams are lost, so the client receives
                // nothing, while the server keeps receiving the client's (its own deadline keeps moving)
                dropToClient = true
                val start = TimeSource.Monotonic.markNow()
                val up = c.openUni()
                while (start.elapsedNow() < idle * 6 / 10) {
                    up.output.writeByte(1)
                    up.output.flush()
                    val sent = TimeSource.Monotonic.markNow()
                    while (sent.elapsedNow() < idle / 10) Thread.onSpinWait()
                }
                withContext(client.dispatcher) {
                    // on the client loop's thread: nothing of the loop runs until this returns
                    client.wake.trySend(Unit) // the timer coroutine is queued first
                    dropToClient = false
                    serverSent = false
                    side.launch {
                        stream.output.writeByte(1)
                        stream.output.flush()
                    }
                    while (!serverSent) Thread.onSpinWait() // the server's datagram is on its way to the client's socket
                    // the client's idle deadline (an idle period after its first packet above) passes; the server's (an
                    // idle period after the client's last packet) does not
                    while (start.elapsedNow() < idle * 125 / 100) Thread.onSpinWait()
                }
                // the timer coroutine runs first: with the datagram processed before it, the deadline moved on
                val got = runCatching { withTimeout(5.seconds) { c.acceptStream().input.readByte() } }
                assertTrue(got.isSuccess, "the client closed a connection whose peer spoke before the idle deadline: $got")
                assertFalse(
                    c.closed.isCompleted,
                    "closed: ${runCatching { c.closed.getCompleted() }}, late wake-ups ${client.lateTimerYieldsForTest}",
                )
            } finally {
                side.cancel()
                client.close()
                server.close()
            }
        }
}
