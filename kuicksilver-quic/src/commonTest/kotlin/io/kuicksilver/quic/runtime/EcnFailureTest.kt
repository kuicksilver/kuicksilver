// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.EcnState
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.api.readExactly
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** A failed ECN validation turns marking off only on the socket of the failed path. */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class EcnFailureTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** An in-memory socket that claims to mark ECT(0) (the memory network bleaches every mark) and records disableEcnMarking. */
    private class MarkingIo(
        private val inner: MemoryDatagramIo,
        ecn: Boolean,
    ) : DatagramIo by inner {
        @Volatile var disabled = 0
        override val capabilities: StateFlow<IoCapabilities> =
            MutableStateFlow(IoCapabilities(ecnSend = ecn, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = false, batch = 1))

        override fun disableEcnMarking() {
            disabled++
        }
    }

    @Test fun failureOnAnExtraPathDisablesThatSocketOnly() =
        runBlocking {
            withTimeout(60.seconds) {
                val net = MemoryNetwork()
                val serverAddr = InetSocketAddress("10.0.0.2", 2222)
                val sio = net.open(serverAddr)
                val first = MarkingIo(net.open(InetSocketAddress("10.0.0.1", 1111)), ecn = false)
                val second = MarkingIo(net.open(InetSocketAddress("10.0.0.3", 3333)), ecn = true)
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server =
                                    QuicServerConfig.Builder(CoreFixtures.server()).build()
                                ; crypto = NullCryptoProvider
                                io = { sio }
                            }.build(),
                    )
                val client =
                    QuicEndpoint.bind(
                        first.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                io = { first }
                            }.build(),
                    )
                try {
                    val accepted = async { server.accept() }
                    val c = client.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    c.migrate(second) // the new path marks ECT(0); the network bleaches it: validation fails on that path
                    val data = ByteArray(256 * 1024) { it.toByte() }
                    val sink = async { s.acceptStream().input.readExactly(data.size) }
                    val st = c.openBidi()
                    st.output.writeFully(data, 0, data.size)
                    st.output.flushAndClose()
                    sink.await()
                    withTimeoutOrNull(10.seconds) { while (second.disabled == 0) delay(20) }
                    assertEquals(1, second.disabled, "the failed path's socket stops marking")
                    assertEquals(0, first.disabled, "the endpoint's socket is left alone")
                    assertTrue(c.stats.ecnState == EcnState.Failed, "ecn ${c.stats.ecnState}")
                    c.close()
                    s.close()
                } finally {
                    client.close()
                    server.close()
                }
            }
        }

    /** An in-memory socket whose capabilities the test changes while connections run on it. */
    private class CapsIo(
        private val inner: MemoryDatagramIo,
    ) : DatagramIo by inner {
        val caps =
            MutableStateFlow(IoCapabilities(ecnSend = true, ecnReceive = false, gsoMaxSegments = 1, gro = false, df = true, batch = 1))
        override val capabilities: StateFlow<IoCapabilities> get() = caps
    }

    @Test fun capabilityLossReachesExistingConnections() =
        runBlocking {
            withTimeout(30.seconds) {
                // a socket that stops marking (or loses DF) after connections started on it: they must stop relying on it too
                val net = MemoryNetwork()
                val serverAddr = InetSocketAddress("10.0.0.2", 2222)
                val sio = net.open(serverAddr)
                val first = CapsIo(net.open(InetSocketAddress("10.0.0.1", 1111)))
                val second = CapsIo(net.open(InetSocketAddress("10.0.0.3", 3333)))
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                crypto = NullCryptoProvider
                                io = { sio }
                            }.build(),
                    )
                val client =
                    QuicEndpoint.bind(
                        first.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                crypto = NullCryptoProvider
                                io = { first }
                            }.build(),
                    )
                try {
                    val accepted = async { server.accept() }
                    val c = client.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    val core = (c as ConnectionRuntime).core
                    assertEquals(true, core.pathCapabilitiesForTest(PathId.Initial)?.ecnSend)
                    first.caps.value = IoCapabilities.Portable
                    withTimeout(5.seconds) { while (core.pathCapabilitiesForTest(PathId.Initial)?.ecnSend != false) delay(10) }
                    assertEquals(false, core.pathCapabilitiesForTest(PathId.Initial)?.df, "DF went with the socket's capabilities")
                    // the same for a migrating client's extra socket
                    val extra = c.addPath(second).id
                    assertEquals(true, core.pathCapabilitiesForTest(extra)?.ecnSend)
                    second.caps.value = IoCapabilities.Portable
                    withTimeout(5.seconds) { while (core.pathCapabilitiesForTest(extra)?.ecnSend != false) delay(10) }
                    c.close()
                    s.close()
                } finally {
                    client.close()
                    server.close()
                }
            }
        }
}
