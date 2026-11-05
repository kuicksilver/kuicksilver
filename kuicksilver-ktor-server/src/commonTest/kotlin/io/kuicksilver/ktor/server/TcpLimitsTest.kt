// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.sockets.InetSocketAddress
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * `maxTcpConnections` and `maxTcpConnectionsPerIp` in the TCP accept loop ([acceptLoop], [TcpLimits]), with a fake accept
 * source on virtual time: what reaches `accept()` and what is handed on to the TLS handshake.
 */
class TcpLimitsTest {
    /** A fake accepted client: its address key and a name for the assertions. */
    private class Client(
        val name: String,
        val key: String? = "ip-a",
    )

    /** The loop over [clients] with [limits]: what was served (with its lease), refused, and how often accept ran. */
    private class Harness(
        val limits: TcpLimits,
    ) {
        val clients = Channel<Client>(Channel.UNLIMITED)
        var accepts = 0
        val served = ArrayList<Pair<Client, TcpLease>>()
        val refused = ArrayList<Client>()

        suspend fun run(): Nothing =
            acceptLoop(
                accept = {
                    accepts++
                    clients.receive()
                },
                isClosed = { false },
                onError = { _, _ -> },
                limits = limits,
                ipKeyOf = { it.key },
                refuse = { refused += it },
            ) { c, lease -> served += c to lease }

        fun lease(name: String): TcpLease = served.first { it.first.name == name }.second
    }

    /**
     * At `maxTcpConnections` the loop stops calling accept() (the slot is taken before it, as Go's `netutil.LimitListener`,
     * Jetty's `ConnectionLimit` and nginx `worker_connections` do), so the kernel backlog holds the next client and the server
     * spends nothing on it; a closed connection lets the next one in.
     */
    @Test fun atTheLimitAcceptingStops() =
        runTest {
            val h = Harness(TcpLimits(maxConnections = 2, maxPerIp = null))
            listOf("1", "2", "3").forEach { h.clients.send(Client(it)) }
            val loop = launch { h.run() }
            runCurrent()
            assertEquals(2, h.accepts, "accept() runs only while a slot is free")
            assertEquals(listOf("1", "2"), h.served.map { it.first.name })
            assertEquals(2, h.limits.connections)
            h.lease("1").release()
            runCurrent()
            assertEquals(listOf("1", "2", "3"), h.served.map { it.first.name }, "the third is accepted once the first closed")
            assertEquals(2, h.limits.connections)
            h.lease("1").release() // a second release of one lease frees nothing
            runCurrent()
            assertEquals(2, h.limits.connections)
            loop.cancel()
        }

    /**
     * Over `maxTcpConnectionsPerIp` a client is refused right after accept (its address is not known before), before it is
     * handed on to the TLS handshake (`serve`); a client from another address is served. The refused one does not hold a
     * slot, and the address may connect again once one of its connections closed.
     */
    @Test fun negative_perIpExcessClosedBeforeTls() =
        runTest {
            val h = Harness(TcpLimits(maxConnections = 10, maxPerIp = 1))
            h.clients.send(Client("a1", "ip-a"))
            h.clients.send(Client("a2", "ip-a"))
            h.clients.send(Client("b1", "ip-b"))
            val loop = launch { h.run() }
            runCurrent()
            assertEquals(listOf("a1", "b1"), h.served.map { it.first.name }, "handed on to TLS")
            assertEquals(listOf("a2"), h.refused.map { it.name }, "closed at accept")
            assertEquals(2, h.limits.connections, "a refused client holds no slot")
            h.lease("a1").release()
            h.clients.send(Client("a3", "ip-a"))
            runCurrent()
            assertEquals(listOf("a1", "b1", "a3"), h.served.map { it.first.name })
            loop.cancel()
        }

    /** A client whose address is not known is not counted per address (it cannot be told apart), only by the connector limit. */
    @Test fun unknownAddressCountsOnlyAgainstTheConnectorLimit() =
        runTest {
            val h = Harness(TcpLimits(maxConnections = 3, maxPerIp = 1))
            repeat(3) { h.clients.send(Client("u$it", key = null)) }
            val loop = launch { h.run() }
            runCurrent()
            assertEquals(3, h.served.size)
            loop.cancel()
        }

    /**
     * A failed accept() gives its slot back: with `maxTcpConnections = 1`, a slot kept by each failure would stop the
     * loop for good after the first EMFILE. The failures still back off (5 ms, doubling: [AcceptLoopTest]).
     */
    @Test fun negative_failedAcceptReturnsItsSlot() =
        runTest {
            val limits = TcpLimits(maxConnections = 1, maxPerIp = null)
            var calls = 0
            val served = ArrayList<String>()
            val loop =
                launch {
                    acceptLoop(
                        accept = {
                            when (++calls) {
                                in 1..3 -> throw IOException("Too many open files")
                                4 -> "client"
                                else -> awaitCancellation() // a further accept would wait for the next client
                            }
                        },
                        isClosed = { false },
                        onError = { _, _ -> },
                        limits = limits,
                    ) { c, _ -> served += c }
                }
            advanceUntilServed { served.isNotEmpty() }
            assertEquals(listOf("client"), served)
            assertEquals(4, calls)
            assertEquals(1, limits.connections)
            loop.cancel()
        }

    /** A serve that fails (cancelled while it checks the client) gives the slot and the address back. */
    @Test fun negative_serveFailureReturnsTheSlot() =
        runTest {
            val limits = TcpLimits(maxConnections = 1, maxPerIp = 1)
            var n = 0
            assertFailsWith<CancellationException> {
                acceptLoop(
                    accept = { if (++n == 1) Client("a1") else awaitCancellation() },
                    isClosed = { false },
                    onError = { _, _ -> },
                    limits = limits,
                    ipKeyOf = { it.key },
                ) { _, _ -> throw CancellationException("stopped") }
            }
            assertEquals(0, limits.connections)
            val again = limits.lease()
            assertTrue(limits.admit(again, "ip-a"), "the address was given back")
        }

    /**
     * The per-address key is made of the address bytes, never a name: no reverse lookup at accept (on the JVM
     * `InetSocketAddress.hostname` may do one), two spellings of one address are one client, an IPv4-mapped peer counts as
     * its IPv4 address, and an IPv6 peer by its whole address (as QUIC `maxConnectionsPerIp`).
     */
    @Test fun negative_perIpKeyNeverResolves() {
        val v6 = assertNotNull(peerIpKey(InetSocketAddress("::1", 1)))
        assertEquals(v6, peerIpKey(InetSocketAddress("0:0:0:0:0:0:0:1", 2)))
        assertEquals(peerIpKey(InetSocketAddress("192.0.2.1", 1)), peerIpKey(InetSocketAddress("::ffff:192.0.2.1", 2)))
        assertNotEquals(peerIpKey(InetSocketAddress("2001:db8::1", 1)), peerIpKey(InetSocketAddress("2001:db8::2", 1)))
        assertEquals("2001:db8:0:0:0:0:0:1", describeIp(parseIpLiteral("2001:db8::1")!!))
        assertEquals("192.0.2.1", describeIp(parseIpLiteral("::ffff:192.0.2.1")!!))
        assertEquals(null, peerIpKey(null))
    }

    @Test fun limitsAreValidated() {
        assertFailsWith<IllegalArgumentException> { KuicksilverApplicationEngine.Configuration().maxTcpConnections = 0 }
        assertFailsWith<IllegalArgumentException> { KuicksilverApplicationEngine.Configuration().maxTcpConnectionsPerIp = 0 }
        val c = KuicksilverApplicationEngine.Configuration()
        assertEquals(10_000, c.maxTcpConnections)
        assertEquals(null, c.maxTcpConnectionsPerIp, "off by default: behind a proxy every client shares one address")
        c.maxTcpConnectionsPerIp = 256
        assertEquals(256, c.maxTcpConnectionsPerIp)
        c.maxTcpConnectionsPerIp = null
        assertEquals(null, c.maxTcpConnectionsPerIp)
    }

    private fun kotlinx.coroutines.test.TestScope.advanceUntilServed(done: () -> Boolean) {
        var steps = 0
        while (!done()) {
            check(++steps < 100) { "nothing was served" }
            testScheduler.advanceTimeBy(1_000)
            runCurrent()
        }
    }
}
