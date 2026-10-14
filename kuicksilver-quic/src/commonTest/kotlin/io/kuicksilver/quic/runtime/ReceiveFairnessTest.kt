// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** The receive loop shares its dispatcher with the timers and the application's commands: a socket that never runs dry must not starve them. */
class ReceiveFairnessTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A socket that, once [busy], answers every receive at once with 30 bytes of junk from a stranger: a flood that never lets the receiver suspend. */
    private class BusyIo(
        private val inner: MemoryDatagramIo,
    ) : DatagramIo by inner {
        @Volatile private var busy = false
        private val stranger = InetSocketAddress("10.0.0.99", 9999)
        private val junk = ByteArray(30) { 0x5a }

        /** Floods from now on; the one real datagram wakes a receiver already parked inside the inner socket. */
        fun goBusy() {
            busy = true
            inner.inbox.trySend(junk to stranger)
        }

        override suspend fun receive(into: PacketBatch): Int {
            if (!busy) return inner.receive(into)
            if (into.count >= into.capacity) return 0
            val i = into.count
            into.buffer(i).copyFrom(junk, 0, 0, junk.size)
            into.setLength(i, junk.size)
            into.setAddress(i, stranger)
            return 1
        }
    }

    @Test fun timersFireUnderContinuousReceive(): Unit =
        runBlocking {
            withTimeout(30.seconds) {
                // a deaf server: only the client's idle timer can end the connection, and it fires only if the flooded receive loop yields
                val net = MemoryNetwork()
                val a = BusyIo(net.open(InetSocketAddress("10.0.0.1", 1111)))
                val b = net.open(InetSocketAddress("10.0.0.2", 2222), deaf = true)
                val server =
                    QuicEndpoint.bind(
                        b.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = NullCryptoProvider
                                io = { b }
                            }.build(),
                    )
                val client =
                    QuicEndpoint.bind(
                        a.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                io = { a }
                            }.build(),
                    )
                // not a child of runBlocking: a starved loop never runs the queued connect, and a cancelled command that was never dispatched cannot complete
                val connects = CoroutineScope(Dispatchers.Default)
                try {
                    val connectJob =
                        connects.async {
                            client.connect(
                                b.localAddress,
                                QuicClientConfig
                                    .Builder(CoreFixtures.client())
                                    .apply {
                                        // a 50 ms initial RTT keeps 3 x PTO (the floor of the idle timeout, RFC 9000 section 10.1) at
                                        // 450 ms: the 500 ms idle timeout decides, not a 3 s floor from the 333 ms default
                                        quic =
                                            quicConfig {
                                                maxIdleTimeout = 500.milliseconds
                                                initialRtt = 50.milliseconds
                                            }
                                    }.build(),
                            )
                        }
                    a.goBusy()
                    // starvation never ends; the 10 s bound leaves room for timer slack on a loaded host (a background-QoS test JVM
                    // on macOS saw each 1 s timer wait return 0.1-0.3 s late without any flood)
                    assertFailsWith<QuicException.ConnectionLost.Timeout> { withTimeout(10.seconds) { connectJob.await() } }
                } finally {
                    connects.cancel()
                    client.close()
                    server.close()
                }
            }
        }
}
