// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.KslDatagramIo
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.tls.KslQuicCrypto
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.lang.management.ManagementFactory
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The loop flushes after every received batch, timer and application write: on the accelerated socket, whose sends never
 * suspend, a flush allocates nothing of its own, no coroutine frame and no copy of the dirty list (P.2).
 */
@OptIn(ExperimentalKuicksilverApi::class)
class FlushAllocationTest {
    @Test fun aFlushOnTheAcceleratedSocketAllocatesNothing() =
        runBlocking {
            KslLoader.ensureLoaded()
            val lo = InetSocketAddress("127.0.0.1", 0)
            val server =
                QuicEndpoint.bind(
                    lo,
                    QuicEndpointConfig
                        .Builder()
                        .apply {
                            this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                            crypto = KslQuicCrypto
                        }.build(),
                ) as EndpointLoop
            val client = QuicEndpoint.bind(lo, QuicEndpointConfig.Builder().apply { crypto = KslQuicCrypto }.build())
            try {
                withTimeout(30.seconds) {
                    // no accelerated socket on this host (a sandbox refusing its probe): nothing to measure, and said so
                    assumeTrue(server.ioForTest is KslDatagramIo, "no accelerated socket on this host: the fast flush is not used")
                    val accepted = async { server.accept() }
                    val c = client.connect(server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val s = accepted.await() as ConnectionRuntime
                    val mx = ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
                    val bytes =
                        withContext(server.dispatcher) {
                            // the connection is idle: each flush walks it (dirty), polls nothing and re-arms its timer. Measured
                            // cold, without JIT warm-up, so escape analysis cannot hide what the loop's own calls allocate
                            server.flush(s.core)
                            var total = 0L
                            repeat(500) {
                                val before = mx.currentThreadAllocatedBytes
                                server.flush(s.core)
                                server.flush()
                                total += mx.currentThreadAllocatedBytes - before
                            }
                            total
                        }
                    // a coroutine frame per flush and a copy of the dirty list were 100+ bytes a flush (100 000+ here); the JIT's
                    // tiering allocates a few hundred bytes now and then
                    assertTrue(bytes <= 8192, "1000 flushes allocated $bytes bytes")
                    c.close()
                    s.close()
                }
            } finally {
                client.close()
                server.close()
            }
        }
}
