// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.native.LeakRegistry
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.core.pto
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * A connection in its closing or draining period (RFC 9000 section 10.2) tells its leak record when the period ends, so the
 * leak sentinel does not take the wait for it, 3 x PTO (about 3 s before the first RTT sample), for slow teardown: the side
 * that closes (closing) and the side that receives the CONNECTION_CLOSE (draining) both.
 */
class ClosingPeriodRecordTest {
    @Test fun bothSidesOfAClosedConnectionNameTheEndOfTheirClosingPeriod() =
        runBlocking {
            assertTrue(LeakRegistry.enabled, "the leak sentinel turns the registry on in every test run")
            withTimeout(30.seconds) {
                val net = MemoryNetwork()
                val serverAddr = InetSocketAddress("10.0.0.2", 2222)
                val sio = net.open(serverAddr)
                val cio = net.open(InetSocketAddress("10.0.0.1", 1111))
                val server =
                    QuicEndpoint.bind(
                        serverAddr,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                this.server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                runtime {
                                    crypto = NullCryptoProvider
                                    io = { sio }
                                }
                            }.build(),
                    )
                val client =
                    QuicEndpoint.bind(
                        cio.localAddress,
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                runtime {
                                    crypto = NullCryptoProvider
                                    io = { cio }
                                }
                            }.build(),
                    )
                try {
                    val mark = LeakRegistry.mark()
                    val accepted = async { server.accept() }
                    val c = client.connect(serverAddr, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    val sc = accepted.await()
                    val records = LeakRegistry.openSince(mark).filter { it.kind == "quic.connection" }
                    assertEquals(2, records.size, "the client's connection and the server's")
                    for (r in records) assertNull(r.closingUntil, "an open connection is in no closing period")
                    val before = TimeSource.Monotonic.markNow()
                    c.close(0, "bye")
                    sc.closed.await() // the server read the CONNECTION_CLOSE: draining
                    for ((r, conn) in records.zip(listOf(c, sc).sortedBy { (it as ConnectionRuntime).leakIdForTest })) {
                        val core = (conn as ConnectionRuntime).core
                        val until = assertNotNull(r.closingUntil, "${r.id}: closing or draining")
                        val noted = assertNotNull(r.closingNoted)
                        // the record names the core's own end: 3 x PTO from the start of the period, told within the loop turn
                        // that started it, so what is left when it is noted is at most 3 x PTO and only the turn's time below
                        // pto() is read from the test thread, not the loop: safe here, as the RTT is frozen once the
                        // connection closes (a closing or draining connection takes no new RTT sample)
                        val period = core.pto() * 3
                        assertEquals(core.pto(), r.closingPto, "${r.id}: the record names the PTO its period was set from")
                        assertEquals(core.timers.closePto, r.closingPto)
                        val left = until - noted
                        assertTrue(left <= period, "${r.id}: $left left of a $period period")
                        assertTrue(period - left < 200.milliseconds, "${r.id}: noted ${period - left} into its period")
                        assertTrue(noted >= before, "noted after the close")
                        // with an RTT sample (in memory: microseconds) the period is far below 3 x 999 ms, the period of a
                        // connection without one
                        assertTrue(until - before < 2.seconds, "3 x PTO with an RTT sample: ${until - before}")
                    }
                } finally {
                    client.close()
                    server.close()
                }
            }
        }
}
