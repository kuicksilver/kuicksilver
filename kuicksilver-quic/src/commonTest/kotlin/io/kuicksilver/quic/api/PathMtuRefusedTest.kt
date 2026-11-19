// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.Initiator
import io.kuicksilver.quic.MemoryDatagramIo
import io.kuicksilver.quic.NonSuspendingSend
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.PathMtuRefusedException
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicServerConfig
import io.kuicksilver.quic.TransportError
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9000 section 14.2.1 where the socket's DF is in DO mode (probe mode refused, or the JVM's portable socket without `ksl`):
 * a forged ICMP message claiming less than 1200 makes the system refuse every datagram to the peer (EMSGSIZE / WSAEMSGSIZE). A
 * refusal of a datagram of at most 1200 bytes ([PathMtuRefusedException], or the accelerated socket's EMSGSIZE count) fails
 * that path (section 14: "cease sending QUIC packets ... on the affected path"): a path other than the active one is closed,
 * the active one ends the connection with a CONNECTION_CLOSE of NO_VIABLE_PATH (an HTTP/3 client then falls back to TCP)
 * instead of losing datagrams until the idle timeout; a larger one stays a lost datagram, and a refusal of a stateless send
 * is never charged to a connection. Fault injection on the in-memory socket.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class PathMtuRefusedTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun ping(
        c: QuicConnection,
        s: QuicConnection,
    ) = coroutineScope {
        val server =
            launch {
                val st = s.acceptStream()
                val got = st.input.readExactly(4)
                st.output.writeFully(got, 0, 4)
                st.output.flushAndClose()
            }
        val st = c.openBidi()
        st.output.writeFully(byteArrayOf(1, 2, 3, 4), 0, 4)
        st.output.flushAndClose()
        assertTrue(st.input.readExactly(4).contentEquals(byteArrayOf(1, 2, 3, 4)))
        server.join()
    }

    @Test fun negative_aRefusalAtOrBelow1200EndsTheClientConnection() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, _) = p.connect()
                    p.clientIo.sendFailure = PathMtuRefusedException(1200)
                    val st = c.openBidi()
                    // the flush may already meet the closed connection
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    }
                    assertNoViablePath(c.closed.await())
                }
            }
        }

    @Test fun negative_aRefusalOnTheServersSocketEndsThatConnectionOnly() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    p.serverIo.sendFailure = PathMtuRefusedException(800)
                    val st = c.openBidi()
                    st.output.writeFully(byteArrayOf(1), 0, 1)
                    st.output.flush() // the server acknowledges: its send is refused
                    assertNoViablePath(s.closed.await())
                    p.serverIo.sendFailure = null
                    val (c2, s2) = p.connect() // the server's endpoint stays up
                    ping(c2, s2)
                    assertFalse(c2.closed.isCompleted)
                    c.close()
                }
            }
        }

    @Test fun aRefusalAbove1200IsALostDatagram() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    p.clientIo.sendFailuresLeft = 1
                    p.clientIo.sendFailure = PathMtuRefusedException(1300)
                    ping(c, s) // its first datagram is refused and sent again
                    assertTrue(p.clientIo.sendFailure == null, "the refusal happened")
                    assertFalse(c.closed.isCompleted, "a refusal above QUIC's floor is a lost datagram, not a failed path")
                }
            }
        }

    private fun assertNoViablePath(e: Throwable) {
        val t = assertIs<QuicException.ConnectionLost.TransportClosed>(e)
        assertEquals(TransportError.NO_VIABLE_PATH, t.code)
        assertEquals(Initiator.Local, t.initiator)
    }

    /** Section 14: a refusal on a path other than the active one closes that path; the connection goes on. */
    @Test fun negative_aRefusalOnAProbedPathClosesThatPathOnly() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    val other = p.net.open(InetSocketAddress("10.0.0.3", 3003))
                    other.sendFailure = PathMtuRefusedException(1200)
                    val path = c.addPath(other)
                    assertFalse(path.probe(), "the path whose socket refuses never validates")
                    assertEquals(PathState.Closed, path.state.value)
                    assertFalse(c.closed.isCompleted, "the connection survives on its active path")
                    ping(c, s)
                }
            }
        }

    /** No DF for the peer's address family (one half of a dual-stack socket): nothing is sent, the connection has no viable path. */
    @Test fun negative_noDontFragmentForThePeerEndsTheConnection() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, _) = p.connect()
                    val noDf = QuicException.DontFragmentUnavailable(4, "test: no DF on the IPv4 half")
                    p.clientIo.sendFailure = noDf
                    val st = c.openBidi()
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    }
                    val closed = assertIs<QuicException.ConnectionLost.NoViablePath>(c.closed.await())
                    assertEquals(noDf, closed.cause)
                }
            }
        }

    /** No DF, no QUIC: a server endpoint whose socket cannot set DF does not start. */
    @Test fun negative_aServerWithoutDontFragmentDoesNotStart() =
        runBlocking<Unit> {
            assertFailsWith<QuicException.DontFragmentUnavailable> {
                QuicEndpoint
                    .bind(
                        InetSocketAddress("127.0.0.1", 0),
                        QuicEndpointConfig
                            .Builder()
                            .apply {
                                server = QuicServerConfig.Builder(CoreFixtures.server()).build()
                                io = { throw QuicException.DontFragmentUnavailable(0, "test: no DF") }
                            }.build(),
                    ).close()
            }
        }

    /** A refusal for a destination none of the connection's paths has is not this connection's: it goes on. */
    @Test fun aRefusalForAnotherDestinationIsIgnored() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    p.clientIo.sendFailuresLeft = 1
                    p.clientIo.sendFailure = PathMtuRefusedException(1200, InetSocketAddress("10.9.9.9", 9))
                    ping(c, s)
                    assertTrue(p.clientIo.sendFailure == null, "the refusal happened")
                    assertFalse(c.closed.isCompleted)
                }
            }
        }

    /** The refused destination as an IPv4-mapped literal is the same peer as its IPv4 spelling. */
    @Test fun negative_aRefusalForTheMappedSpellingOfThePeerEndsTheConnection() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, _) = p.connect()
                    p.clientIo.sendFailure = PathMtuRefusedException(1200, InetSocketAddress("::ffff:10.0.0.2", 2222))
                    val st = c.openBidi()
                    runCatching {
                        st.output.writeFully(byteArrayOf(1), 0, 1)
                        st.output.flush()
                    }
                    assertNoViablePath(c.closed.await())
                }
            }
        }

    /** The accelerated socket names a refused datagram by its length: placed only when one destination has that length. */
    @Test fun aRefusedLengthIsPlacedOnlyWhenOneDestinationHasIt() {
        val a = InetSocketAddress("10.0.0.2", 2222)
        val b = InetSocketAddress("10.0.0.3", 3333)
        PacketBatch(3).use { batch ->
            fun slot(
                i: Int,
                len: Int,
                to: InetSocketAddress,
            ) {
                batch.setLength(i, len)
                batch.setAddress(i, to)
            }
            slot(0, 1200, a)
            slot(1, 100, b)
            slot(2, 1200, InetSocketAddress("::ffff:10.0.0.2", 2222))
            assertEquals(
                a,
                io.kuicksilver.quic.runtime
                    .slotOfLength(batch, 1200),
                "one peer, two spellings",
            )
            assertEquals(
                b,
                io.kuicksilver.quic.runtime
                    .slotOfLength(batch, 100),
            )
            assertEquals(
                null,
                io.kuicksilver.quic.runtime
                    .slotOfLength(batch, 500),
                "no datagram of that length",
            )
            slot(1, 1200, b)
            assertEquals(
                null,
                io.kuicksilver.quic.runtime
                    .slotOfLength(batch, 1200),
                "two destinations: not placed",
            )
        }
    }

    /**
     * A refusal reported after a stateless send (here a Version Negotiation answer, through an accelerated-style socket that
     * reports EMSGSIZE after the batch) is taken with that send: the next connection batch on the socket is not charged with it.
     */
    @Test fun negative_aRefusedStatelessSendDoesNotEndTheNextConnection() =
        runBlocking<Unit> {
            var wrapped: EmsgsizeIo? = null
            ApiPair
                .open(serverConfigure = {
                    val inner = io!!
                    io = { a -> EmsgsizeIo(inner(a) as MemoryDatagramIo).also { wrapped = it } }
                })
                .use { p ->
                    withTimeout(30.seconds) {
                        val (c, s) = p.connect()
                        val w = wrapped!!
                        val stranger = InetSocketAddress("10.0.0.66", 666)
                        w.refuseTo = stranger
                        // a long-header datagram of an unknown version: the server answers with Version Negotiation (stateless)
                        val vn = ByteArray(1200)
                        vn[0] = 0xc0.toByte()
                        byteArrayOf(0x1a, 0x2a, 0x3a, 0x4a).copyInto(vn, 1)
                        vn[5] = 8
                        vn[14] = 8
                        p.net.deliver(stranger, p.serverIo.localAddress, vn)
                        while (!w.refused) kotlinx.coroutines.yield()
                        ping(c, s) // the server's connection sends on the same socket
                        assertFalse(s.closed.isCompleted, "the stateless send's refusal was not charged to the connection")
                        assertTrue(w.takes > 0, "the loop asked the socket for refusals: ${w.takes}")
                    }
                }
        }
}

/** A socket that reports one batch to [refuseTo] as refused (EMSGSIZE, as the accelerated socket counts it) after sending it. */
private class EmsgsizeIo(
    private val inner: MemoryDatagramIo,
) : DatagramIo by inner,
    NonSuspendingSend {
    @kotlin.concurrent.Volatile
    var refuseTo: InetSocketAddress? = null

    @kotlin.concurrent.Volatile
    var refused = false
    private var pending = 0

    override suspend fun send(batch: PacketBatch): Int = trySend(batch)

    override fun trySend(batch: PacketBatch): Int {
        val n = inner.trySend(batch)
        val r = refuseTo
        if (r != null) {
            for (i in 0 until batch.count) {
                if (batch.address(i) == r) {
                    pending = batch.length(i)
                    refuseTo = null
                    refused = true
                }
            }
        }
        return n
    }

    @kotlin.concurrent.Volatile
    var takes = 0

    override fun takeEmsgsize(): Int {
        takes++
        return pending.also { pending = 0 }
    }
}
