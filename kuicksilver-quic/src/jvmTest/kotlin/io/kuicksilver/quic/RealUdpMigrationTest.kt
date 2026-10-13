// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.readExactly
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** A client over two real UDP sockets on loopback moves a 10 MiB transfer from one to the other with `migrate` (RFC 9000 section 9.2). */
@OptIn(ExperimentalKuicksilverApi::class)
class RealUdpMigrationTest {
    @Test fun nioClientMigratesBetweenTwoSockets() =
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
                    val data = ByteArray(10 shl 20) { (it * 3).toByte() }
                    val sink =
                        async {
                            val st = s.acceptStream()
                            st.input.readExactly(data.size)
                        }
                    val st = c.openBidi()
                    val writer =
                        launch {
                            st.output.writeFully(data, 0, data.size)
                            st.output.flushAndClose()
                        }
                    while (s.stats.bytesReceived < (3L shl 20)) kotlinx.coroutines.delay(20)
                    val change = c.migrate(DatagramIo.open(InetSocketAddress("127.0.0.1", 0)))
                    assertEquals(PathChangeReason.ActiveMigration, change.reason)
                    writer.join()
                    assertContentEquals(data, sink.await())
                    assertEquals(
                        change.new.localAddress.port,
                        s.core.remoteAddressForTest.port,
                        "the server now talks to the second socket",
                    )
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }

    @Test fun closeAfterMigrationReachesTheServer() =
        runBlocking {
            KslLoader.ensureLoaded()
            val server =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto = KslQuicCrypto
                        }.build(),
                )
            val client =
                QuicEndpoint.bind(
                    InetSocketAddress("127.0.0.1", 0),
                    QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build(),
                )
            try {
                withTimeout(30.seconds) {
                    // the soak found server connections that outlived a migrated client's close until their idle timeout
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await()
                    val echo =
                        launch {
                            try {
                                while (true) {
                                    val st = s.acceptStream()
                                    val got = st.input.readExactly(1000)
                                    st.output.writeFully(got, 0, got.size)
                                    st.output.flushAndClose()
                                }
                            } catch (_: QuicException.ConnectionLost) {
                                // the client's close ends the accept loop
                            }
                        }

                    suspend fun roundTrip() {
                        val st = c.openBidi()
                        st.output.writeFully(ByteArray(1000), 0, 1000)
                        st.output.flushAndClose()
                        st.input.readExactly(1000)
                    }
                    roundTrip()
                    c.migrate(DatagramIo.open(InetSocketAddress("127.0.0.1", 0)))
                    roundTrip()
                    c.close(7, "moved")
                    val r = withTimeout(5.seconds) { s.closed.await() }
                    assertEquals(7L, (r as QuicException.ConnectionLost.ApplicationClosed).code)
                    echo.cancel()
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
