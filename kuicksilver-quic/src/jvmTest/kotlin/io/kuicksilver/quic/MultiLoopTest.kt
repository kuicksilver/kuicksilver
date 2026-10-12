// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.readExactly
import io.kuicksilver.quic.runtime.LoopGroup
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.KslUdpSocket
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Several endpoint loops on one port with SO_REUSEPORT (threat-model 3.4); Linux only: the kernel must hash flows over the
 * sockets. Darwin has the accelerated socket but delivers unicast UDP to one SO_REUSEPORT socket only, so there (and where
 * the accelerated socket is absent) the tests report skipped and `loops > 1` is refused.
 */
class MultiLoopTest {
    private val lo = InetSocketAddress("127.0.0.1", 0)

    private fun ready(): Boolean {
        KslLoader.ensureLoaded()
        return KslUdpSocket.supported && System.getProperty("os.name").lowercase().contains("linux")
    }

    private fun serverConfig(loops: Int) =
        QuicEndpointConfig
            .Builder()
            .apply {
                server =
                    QuicServerConfig.Builder(CoreFixtures.server()).build()
                ; crypto = KslQuicCrypto
                this.loops = loops
            }.build()

    private val clientConfig = QuicClientConfig.Builder(CoreFixtures.client()).build()

    @Test fun fourLoopsShareOnePort() =
        runBlocking {
            assumeTrue(ready(), "needs SO_REUSEPORT flow hashing (Linux)")
            val server = QuicEndpoint.bind(lo, serverConfig(4))
            val group = server as LoopGroup
            val clients = List(20) { QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build()) }
            try {
                withTimeout(300.seconds) {
                    var acceptedCount = 0
                    val echo =
                        launch {
                            while (true) {
                                val s = server.accept()
                                acceptedCount++
                                launch {
                                    val st = s.acceptStream()
                                    val got =
                                        st.input.readExactly(1 shl 20)
                                    ; st.output.writeFully(got, 0, got.size)
                                    st.output.flushAndClose()
                                }
                            }
                        }
                    val data = ByteArray(1 shl 20) { (it * 13).toByte() }
                    // each echo is checked inside its coroutine: a hundred 1 MiB results kept until awaitAll would be 100 MiB of heap for nothing
                    val jobs =
                        clients.flatMap { ep ->
                            List(5) {
                                async {
                                    val c = ep.connect(server.localAddress, clientConfig)
                                    val st = c.openBidi()
                                    launch {
                                        st.output.writeFully(data, 0, data.size)
                                        st.output.flushAndClose()
                                    }
                                    val got = st.input.readExactly(data.size)
                                    c.close()
                                    assertContentEquals(data, got)
                                }
                            }
                        }
                    jobs.awaitAll()
                    val perLoop = group.statsForTest().map { it.connectionsCreated }
                    assertEquals(100L, perLoop.sum(), "every connection was created on some loop")
                    assertTrue(perLoop.count { it > 0 } >= 2, "connections spread over loops: $perLoop")
                    echo.cancel()
                }
            } finally {
                clients.forEach { it.close() }
                server.close()
            }
        }

    @Test fun forwardedDatagramReachesOwner() =
        runBlocking {
            assumeTrue(ready(), "needs SO_REUSEPORT flow hashing (Linux)")
            val server = QuicEndpoint.bind(lo, serverConfig(2))
            val group = server as LoopGroup
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(120.seconds) {
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, clientConfig)
                    val s = accepted.await()
                    val owner = group.connectionsPerLoopForTest().indexOfFirst { it > 0 }
                    val other = 1 - owner
                    // every datagram of the owner's socket is handed to the other loop first, as a NAT rebind onto its socket would
                    group.misrouteForTest(from = owner, to = other)
                    val data = ByteArray(1 shl 20) { (it * 3).toByte() }
                    val echo =
                        launch {
                            val st = s.acceptStream()
                            val got = st.input.readExactly(data.size)
                            st.output.writeFully(got, 0, got.size)
                            st.output.flushAndClose()
                        }
                    val st = c.openBidi()
                    launch {
                        st.output.writeFully(data, 0, data.size)
                        st.output.flushAndClose()
                    }
                    assertContentEquals(data, st.input.readExactly(data.size))
                    echo.join()
                    assertTrue(group.forwardedForTest(other) > 0, "the other loop forwarded to the owner")
                    assertEquals(1, group.connectionsPerLoopForTest()[owner], "the connection stayed with its owner")
                    assertEquals(
                        0L,
                        group.statsForTest().sumOf {
                            it.statelessResets
                        },
                        "no loop answered with a Stateless Reset",
                    ) // negative_resetNotFromOtherLoop at the runtime level
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    @Test fun loopsAboveOneOnPortableIoRejected() =
        runBlocking {
            KslLoader.ensureLoaded()
            val cfg =
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                        crypto =
                            KslQuicCrypto
                        loops = 2
                        io = { DatagramIo.open(it, IoPreference.Portable) }
                    }.build()
            assertFailsWith<UnsupportedOperationException> { QuicEndpoint.bind(lo, cfg) }
            if (!ready()) assertFailsWith<UnsupportedOperationException> { QuicEndpoint.bind(lo, serverConfig(2)) } // macOS: no flow hashing
            // loops > 1 needs a server
            assertFailsWith<IllegalArgumentException> { QuicEndpointConfig.Builder().apply { loops = 2 }.build() }
            Unit
        }
}
