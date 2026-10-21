// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.MigrationEvent
import io.kuicksilver.quic.NetworkMigrator
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.PathId
import io.kuicksilver.quic.QuicClientConfig
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.SocketDefunctException
import io.kuicksilver.quic.activePath
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
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
 * A socket the system took away (iOS suspends the app, `ENOTCONN` on return) is a lost path, not a failed connection or endpoint:
 * fault injection on the in-memory socket ([io.kuicksilver.quic.MemoryDatagramIo.failWith]).
 */
@OptIn(ExperimentalKuicksilverApi::class)
class SocketLostTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val enotconn = SocketDefunctException("socket defunct: sendmsg: Socket is not connected", 57)

    /** Every path event of [c] from now on; cancel the job when done. */
    private fun kotlinx.coroutines.CoroutineScope.pathEventsOf(c: QuicConnection): Pair<Channel<PathEvent>, Job> {
        val ch = Channel<PathEvent>(Channel.UNLIMITED)
        val job = launch(start = CoroutineStart.UNDISPATCHED) { c.pathEvents.collect { ch.send(it) } }
        return ch to job
    }

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

    private suspend fun <T> Channel<PathEvent>.next(type: kotlin.reflect.KClass<*>): T {
        while (true) {
            val e = receive()
            @Suppress("UNCHECKED_CAST")
            if (type.isInstance(e)) return e as T
        }
    }

    @Test fun endpointSocketLostKeepsTheConnectionUntilItMoves() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val (events, collector) = pathEventsOf(c)
                    awaitSpareConnectionId(c) // the server's NEW_CONNECTION_ID arrived: a move needs an unused ID (RFC 9000 section 9.5)
                    p.clientIo.failWith(enotconn)
                    val lost = events.next<PathEvent.SocketLost>(PathEvent.SocketLost::class)
                    assertEquals(PathId.Initial, lost.path.id)
                    assertEquals(57, lost.cause.errno)
                    assertFalse(c.closed.isCompleted, "the connection survives the lost socket")
                    // a new connection on the dead socket fails at once instead of timing out
                    assertFailsWith<SocketDefunctException> {
                        p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    }
                    // the documented recovery: migrate to a fresh socket, close the lost path
                    val changed = c.migrate(p.net.open(InetSocketAddress("10.0.0.9", 9999)))
                    changed.old.close()
                    assertEquals(InetSocketAddress("10.0.0.9", 9999), c.activePath!!.localAddress)
                    ping(c, s)
                    collector.cancel()
                    c.close()
                }
            }
        }

    /**
     * The only socket lost before the handshake is confirmed: the client cannot migrate (RFC 9000 section 9) and can neither
     * send its Finished nor receive HANDSHAKE_DONE, so the connection ends at once with [QuicException.ConnectionLost.NoViablePath]
     * instead of waiting for the idle timeout (it used to keep `migrate` suspended for 30 s).
     */
    @Test fun socketLostBeforeConfirmationEndsTheConnectionAtOnce() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                var fromClient = 0
                // after the ClientHello nothing of the client arrives: no Finished, so no HANDSHAKE_DONE
                p.net.lose = { from, _, _ -> from == p.clientIo.localAddress && fromClient++ >= 1 }
                withTimeout(5.seconds) {
                    // the client completes; the server, without the client's Finished, never does (so no accept)
                    val c = p.client.connect(p.server.localAddress, QuicClientConfig.Builder(CoreFixtures.client()).build())
                    assertFalse(c.closed.isCompleted)
                    p.clientIo.failWith(enotconn)
                    assertIs<QuicException.ConnectionLost.NoViablePath>(c.closed.await())
                    assertFailsWith<QuicException.ConnectionLost.NoViablePath> {
                        c.migrate(
                            p.net.open(InetSocketAddress("10.0.0.9", 9999)),
                        )
                    }
                }
            }
        }

    @Test fun lostMigratedSocketIsReportedNotFatal() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val (events, collector) = pathEventsOf(c)
                    awaitSpareConnectionId(c)
                    val io = p.net.open(InetSocketAddress("10.0.0.5", 5555))
                    val moved = c.migrate(io)
                    io.failWith(enotconn)
                    val lost = events.next<PathEvent.SocketLost>(PathEvent.SocketLost::class)
                    assertEquals(moved.new.id, lost.path.id)
                    assertFalse(c.closed.isCompleted, "a lost path socket no longer fails the connection")
                    awaitSpareConnectionId(c)
                    val back = c.migrate(p.net.open(InetSocketAddress("10.0.0.6", 6666)))
                    back.old.close()
                    ping(c, s)
                    collector.cancel()
                    c.close()
                }
            }
        }

    @Test fun aLostPathSocketIsForgottenWhenItsConnectionEnds() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, _) = p.connect()
                    val (events, collector) = pathEventsOf(c)
                    awaitSpareConnectionId(c)
                    val io = p.net.open(InetSocketAddress("10.0.0.5", 5555))
                    c.migrate(io)
                    io.failWith(enotconn)
                    events.next<PathEvent.SocketLost>(PathEvent.SocketLost::class)
                    val loop = p.client as io.kuicksilver.quic.runtime.EndpointLoop
                    assertEquals(1, loop.defunctCountForTest())
                    // the connection ends on the lost path: its sockets are released when it reaches Closed, after the closing
                    // period (the runtime keeps them until then), and the loop must not keep remembering the lost one
                    c.close()
                    c.closed.await()
                    withTimeout(10.seconds) {
                        while (kotlinx.coroutines.withContext(loop.dispatcher) { loop.runtimes.isNotEmpty() }) kotlinx.coroutines.yield()
                    }
                    assertEquals(0, loop.defunctCountForTest(), "the lost socket of an ended connection is still remembered")
                    collector.cancel()
                }
            }
        }

    @Test fun migratorReplacesALostActiveSocketOnTheSameNetwork() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val opened = mutableListOf<io.kuicksilver.quic.MemoryDatagramIo>()
                    val m =
                        NetworkMigrator(c, MutableStateFlow<Int?>(1), { n ->
                            p.net.open(InetSocketAddress("10.0.$n.${opened.size + 1}", 7000)).also { opened += it }
                        }, this)
                    val events = Channel<MigrationEvent<Int>>(Channel.UNLIMITED)
                    val collector = launch(start = CoroutineStart.UNDISPATCHED) { m.events.collect { events.send(it) } }
                    m.start()
                    m.network.first1()
                    awaitSpareConnectionId(c) // a move needs an unused ID of the server (RFC 9000 section 9.5)
                    p.clientIo.failWith(enotconn)
                    val e = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(1 to 1, e.old to e.new)
                    assertEquals(opened.single().localAddress, c.activePath!!.localAddress)
                    ping(c, s)
                    // and again on the migrated socket
                    awaitSpareConnectionId(c)
                    opened.single().failWith(enotconn)
                    val e2 = assertIs<MigrationEvent.Migrated<Int>>(events.receive())
                    assertEquals(opened[1].localAddress, e2.path.localAddress)
                    // the lost socket is released (the old path closes on the loop right after the switch)
                    withTimeout(10.seconds) { while (!opened[0].closed) kotlinx.coroutines.yield() }
                    ping(c, s)
                    m.close()
                    collector.cancel()
                    c.close()
                }
            }
        }

    private suspend fun kotlinx.coroutines.flow.StateFlow<Int?>.first1() {
        withTimeout(10.seconds) { while (value != 1) kotlinx.coroutines.yield() }
    }

    @Test fun negative_serverSocketLossStillEndsTheServerEndpoint() =
        runBlocking<Unit> {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (_, s) = p.connect()
                    p.serverIo.failWith(enotconn)
                    // its clients address this port: a server cannot move, so its endpoint ends as for any socket failure
                    assertIs<io.kuicksilver.quic.QuicException.ConnectionLost.Internal>(s.closed.await())
                    assertFailsWith<io.kuicksilver.quic.QuicException.EndpointClosing> { p.server.accept() }
                }
                Unit
            }
        }
}
