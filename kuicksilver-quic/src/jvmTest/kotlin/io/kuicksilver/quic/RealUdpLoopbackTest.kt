// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.close
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.readExactly
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class)
class RealUdpLoopbackTest {
    @Test fun nioServerClientTenMiB() =
        runBlocking {
            KslLoader.ensureLoaded()
            val server =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server =
                                QuicServerConfig.Builder(CoreFixtures.server()).build()
                            ; crypto = KslQuicCrypto
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build(),
                )
            try {
                withTimeout(120.seconds) {
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    assertEquals("hq-interop", c.negotiatedAlpn)
                    val data = ByteArray(10 shl 20) { (it * 3).toByte() }
                    val sink =
                        async {
                            val st = s.acceptStream()
                            st.input.readExactly(data.size)
                        }
                    val st = c.openBidi()
                    st.output.writeFully(data, 0, data.size)
                    st.output.flushAndClose()
                    assertContentEquals(data, sink.await())
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
