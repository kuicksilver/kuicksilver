// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.toByteArray
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

@OptIn(ExperimentalKuicksilverApi::class)
class KtorDatagramIoTest {
    @Test fun loopbackClientSendReceive() =
        runBlocking {
            val a = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            val b = DatagramIo.open(InetSocketAddress("127.0.0.1", 0))
            try {
                val out = PacketBatch(1)
                out.buffer(0).copyFrom(byteArrayOf(5, 6, 7), 0, 0, 3)
                out.setLength(0, 3)
                out.setAddress(0, b.localAddress)
                assertEquals(1, a.send(out))
                val inb = PacketBatch(4)
                withTimeout(5.seconds) { while (inb.count == 0) b.receive(inb) }
                assertContentEquals(byteArrayOf(5, 6, 7), inb.buffer(0).toByteArray(inb.length(0)))
                assertEquals(a.localAddress.port, inb.address(0)!!.port)
                out.close()
                inb.close()
            } finally {
                a.close()
                b.close()
            }
        }

    /**
     * A refused bind (the port is taken) leaves nothing behind: before, every refusal leaked its `SelectorManager`, a
     * selection thread of `Dispatchers.IO` and a pipe pair, so 64 of them (an ephemeral `port = 0` server retrying taken
     * UDP twins, a client retrying) starved `Dispatchers.IO` and hung whatever ran there next, Ktor's server stop included.
     */
    @Test fun negative_refusedPortableBindReleasesItsSelector() =
        runBlocking {
            val held = DatagramIo.open(InetSocketAddress("127.0.0.1", 0), IoPreference.Portable)
            try {
                val taken = InetSocketAddress("127.0.0.1", held.localAddress.port)
                assertFailsWith<Throwable> { DatagramIo.open(taken, IoPreference.Portable).close() } // warm-up
                val before = openDescriptors()
                repeat(20) { assertFailsWith<Throwable> { DatagramIo.open(taken, IoPreference.Portable).close() } }
                // the default (accelerated, then portable) path, which the HTTP/3 server binds with
                repeat(20) { assertFailsWith<Throwable> { DatagramIo.open(taken).close() } }
                val leaked = openDescriptors() - before
                assertTrue(leaked < 10, "40 refused binds left $leaked descriptors open")
            } finally {
                held.close()
            }
        }

    /**
     * ktor-network 3.6.0's Native sockets put `::` into every IPv6 sockaddr (Ktor issue KTOR-10017): the portable
     * socket would bind `::` (every interface, IPv4 too) for `::1`. It refuses instead of binding somewhere else.
     */
    @Test fun negative_portableRefusesASpecificIpv6Address() =
        runBlocking {
            assertFailsWith<UnsupportedOperationException> { DatagramIo.open(InetSocketAddress("::1", 0), IoPreference.Portable).close() }
            Unit
        }

    /** ... and refuses to send to an IPv6 address, which ktor-network would send to `::` (the local host) instead. */
    @Test fun negative_portableRefusesIpv6Destinations() =
        runBlocking {
            val a = DatagramIo.open(InetSocketAddress("0.0.0.0", 0), IoPreference.Portable)
            val out = PacketBatch(1)
            try {
                out.buffer(0).copyFrom(byteArrayOf(1), 0, 0, 1)
                out.setLength(0, 1)
                out.setAddress(0, InetSocketAddress("2001:db8::1", 4433))
                assertFailsWith<IOException> { a.send(out) }
                assertFailsWith<IOException> { a.trySend(out) }
                Unit
            } finally {
                out.close()
                a.close()
            }
        }

    /** `::` is what ktor-network binds anyway: allowed (a host without IPv6 fails with its own error). */
    @Test fun portableBindsTheIpv6Wildcard() =
        runBlocking {
            val r = runCatching { DatagramIo.open(InetSocketAddress("::", 0), IoPreference.Portable).close() }
            assertTrue(r.exceptionOrNull() !is UnsupportedOperationException, "$r")
        }

    private fun openDescriptors(): Int = openHandleCount()
}
