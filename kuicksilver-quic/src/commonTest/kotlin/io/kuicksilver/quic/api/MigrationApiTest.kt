// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.api

import io.ktor.network.sockets.InetSocketAddress
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.DelicateKuicksilverApi
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.PathChangeReason
import io.kuicksilver.quic.PathEvent
import io.kuicksilver.quic.PathState
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.runtime.ConnectionRuntime
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
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

/** RFC 9000 section 9: client-initiated migration through the coroutine API, over the in-memory network (all platforms). */
@OptIn(ExperimentalKuicksilverApi::class, DelicateKuicksilverApi::class)
class MigrationApiTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val newAddr = InetSocketAddress("10.0.0.3", 3333)

    /** Echo [size] bytes through [c]/[s]; [midway] runs after [at] bytes were echoed back. */
    private suspend fun echo(
        c: QuicConnection,
        s: QuicConnection,
        size: Int,
        at: Int = -1,
        midway: suspend () -> Unit = {},
    ): Boolean =
        kotlinx.coroutines.coroutineScope {
            val data = ByteArray(size) { (it * 7).toByte() }
            val server =
                launch {
                    val st = s.acceptStream()
                    val buf = ByteArray(16384)
                    var total = 0
                    while (total <
                        size
                    ) {
                        val n = st.input.readAvailable(buf, 0, buf.size)
                        if (n <=
                            0
                        ) {
                            break
                        }
                        st.output.writeFully(buf, 0, n)
                        st.output.flush()
                        total += n
                    }
                    st.output.flushAndClose()
                }
            val st = c.openBidi()
            val writer =
                launch {
                    st.output.writeFully(data, 0, size)
                    st.output.flushAndClose()
                }
            val got = ByteArray(size)
            var off = 0
            var fired = at < 0
            while (off <
                size
            ) {
                val n = st.input.readAvailable(got, off, size - off)
                if (n <=
                    0
                ) {
                    break
                }
                off += n
                if (!fired && off >= at) {
                    fired = true
                    midway()
                }
            }
            writer.join()
            server.join()
            off == size && got.contentEquals(data)
        }

    @Test fun migrateMovesTrafficToNewIo() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    val (c, s) = p.connect()
                    val io2 = p.net.open(newAddr)
                    var change: PathEvent.Changed? = null
                    assertTrue(echo(c, s, 10 shl 20, at = 3 shl 20) { change = c.migrate(io2) }, "10 MiB echoed across the migration")
                    val ch = change!!
                    assertEquals(PathChangeReason.ActiveMigration, ch.reason)
                    assertEquals(newAddr, ch.new.localAddress)
                    assertEquals(PathState.Validated, ch.new.state.value)
                    assertTrue(
                        io2.sent > 0 && io2.received > 0,
                        "traffic moved to the new socket: sent ${io2.sent} received ${io2.received}",
                    )
                    // the server probes the client's previous address once it moves (RFC 9000 section 9.3.3); that probe and its
                    // retries are path validation, not traffic, so the count starts once the server has no path left to validate
                    withTimeout(10.seconds) { while (s.paths.any { it.state.value == PathState.Validating }) delay(10) }
                    val oldIo = p.clientIo
                    val oldAfter = oldIo.received
                    delay(1.seconds)
                    assertEquals(oldAfter, oldIo.received, "the old socket receives nothing once the server moved")
                    assertEquals(2, c.paths.size)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun closeAfterMigrationReachesThePeer() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    // the CONNECTION_CLOSE goes out on the new path; without it the server keeps the connection until its idle timeout
                    val (c, s) = p.connect()
                    assertTrue(echo(c, s, 4 shl 10))
                    c.migrate(p.net.open(newAddr))
                    assertTrue(echo(c, s, 4 shl 10))
                    c.close(7, "moved")
                    val sr = withTimeout(5.seconds) { s.closed.await() }
                    assertIs<QuicException.ConnectionLost.ApplicationClosed>(sr)
                    assertEquals(7L, sr.code)
                }
            }
        }

    @Test fun serverPathListStaysBoundedAcrossMigrations() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(60.seconds) {
                    // the core keeps at most four paths and evicts the oldest; the server's runtime must drop the evicted ones too (six moves: seven addresses)
                    val (c, s) = p.connect()
                    for (i in 1..6) {
                        val change = c.migrate(p.net.open(InetSocketAddress("10.0.1.$i", 1000 + i)))
                        change.old.close()
                        assertTrue(echo(c, s, 4 shl 10), "echo after migration $i")
                        // the server probes each previous address (RFC 9000 section 9.3.3) and never evicts a path under validation:
                        // the next move waits until the probe of the closed address has failed
                        withTimeout(10.seconds) { while (s.paths.any { it.state.value == PathState.Validating }) delay(10) }
                    }
                    val rt = s as ConnectionRuntime
                    assertTrue(s.paths.size <= 4, "server paths: ${s.paths}")
                    assertTrue(rt.pathCountForTest <= 4, "server path runtimes: ${rt.pathCountForTest}")
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun closingTheActivePathIsRefused() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    // the active path cannot be closed; the attempt neither closes its socket nor cuts the connection
                    val (c, s) = p.connect()
                    val io2 = p.net.open(newAddr)
                    val change = c.migrate(io2)
                    assertFailsWith<IllegalStateException> { change.new.close() }
                    assertFalse(io2.closed, "the active path's socket stays open")
                    assertEquals(PathState.Validated, change.new.state.value)
                    assertTrue(echo(c, s, 64 shl 10), "the connection still works on its active path")
                    change.old.close()
                    // a fallback path closes normally
                    withTimeout(5.seconds) { while (change.old.state.value != PathState.Closed) delay(10) }
                    assertTrue(echo(c, s, 64 shl 10))
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun addPathThatFailsClosesTheCallersSocket() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    // a socket handed to addPath is either adopted by a path or closed, never leaked
                    val (c, s) = p.connect()
                    val cancelled = p.net.open(InetSocketAddress("10.0.0.3", 3001))
                    val job = launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.addPath(cancelled) }
                    job.cancel()
                    job.join()
                    assertTrue(
                        cancelled.closed ||
                            c.paths.any {
                                it.localAddress == cancelled.localAddress
                            },
                        "a cancelled addPath closed the socket or adopted it",
                    )
                    c.close(0, "done")
                    withTimeout(5.seconds) { c.closed.await() }
                    val late = p.net.open(InetSocketAddress("10.0.0.3", 3002))
                    assertFailsWith<QuicException.ConnectionLost> { c.addPath(late) }
                    assertTrue(late.closed, "addPath on a closed connection closes the socket")
                    s.close()
                }
            }
        }

    @Test fun probeWithoutSwitchKeepsCurrentPath() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val path = c.addPath(p.net.open(newAddr))
                    assertTrue(path.probe())
                    assertEquals(PathState.Validated, path.state.value)
                    assertTrue(echo(c, s, 64 shl 10))
                    assertEquals(c.paths[0].id, c.core.path.id, "still on the first path")
                    assertTrue(p.clientIo.received > 0)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun probeFailsOnDeadPath() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    val events = async { c.pathEvents.first() }
                    val dead = p.net.open(newAddr, deaf = true)
                    val path = c.addPath(dead)
                    assertFalse(path.probe(), "a socket whose datagrams vanish never validates")
                    assertEquals(PathState.Failed, path.state.value)
                    assertIs<PathEvent.Failed>(events.await())
                    assertTrue(echo(c, s, 64 shl 10), "traffic stays on the old path")
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun migrateWhenPeerDisabledMigrationThrows() =
        runBlocking {
            ApiPair.open(serverQuic = quicConfig { allowMigration = false }).use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val e = assertFailsWith<IllegalStateException> { c.migrate(p.net.open(newAddr)) }
                    assertTrue(e.message!!.contains("disable_active_migration"), e.message)
                    assertTrue(echo(c, s, 1024))
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun addPathBeyondFourThrows() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    for (i in 1..3) c.addPath(p.net.open(InetSocketAddress("10.0.0.3", 3000 + i)))
                    assertFailsWith<IllegalStateException> { c.addPath(p.net.open(InetSocketAddress("10.0.0.3", 3999))) }
                    assertEquals(4, c.paths.size)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun eachPathReportsItsOwnRemoteAddress() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    // the client moves to another socket: on the server the old path is the client's old address and the new one its
                    // new address, in the path events and in QuicConnection.paths alike
                    val (c, s) = p.connect()
                    val clientOld = p.clientIo.localAddress
                    val serverEvents = kotlinx.coroutines.channels.Channel<PathEvent>(kotlinx.coroutines.channels.Channel.UNLIMITED)
                    val collector =
                        launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { s.pathEvents.collect { serverEvents.send(it) } }
                    c.migrate(p.net.open(newAddr))
                    assertTrue(echo(c, s, 4 shl 10))
                    val changed =
                        withTimeout(10.seconds) {
                            var e: PathEvent
                            do e = serverEvents.receive() while (e !is PathEvent.Changed)
                            e
                        }
                    assertEquals(clientOld, changed.old.remoteAddress, "the path the client left")
                    assertEquals(newAddr, changed.new.remoteAddress, "the path the client moved to")
                    val remotes = s.paths.map { it.remoteAddress }
                    assertTrue(newAddr in remotes, "$remotes")
                    for (path in s.paths) {
                        assertEquals(if (path.id == changed.old.id) clientOld else newAddr, path.remoteAddress, "$path")
                    }
                    collector.cancel()
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun pathEventsOrdered() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val events = async { c.pathEvents.take(2).toList() }
                    c.migrate(p.net.open(newAddr))
                    val l = events.await()
                    assertIs<PathEvent.Validated>(l[0])
                    assertIs<PathEvent.Changed>(l[1])
                    assertEquals(l[0].let { (it as PathEvent.Validated).path.id }, (l[1] as PathEvent.Changed).new.id)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun allPathsFailedClosesNoViablePath() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    val (c, s) = p.connect()
                    val io2 = p.net.open(newAddr)
                    val change = c.migrate(io2)
                    change.old.close() // the first path is gone: no fallback
                    p.net.cut(newAddr) // and the only remaining address goes dark
                    assertFalse(change.new.probe(), "the active path cannot be validated any more")
                    assertIs<QuicException.ConnectionLost.NoViablePath>(c.closed.await())
                    s.close()
                }
            }
        }

    @Test fun pathChangedIsAPathEventMember() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(30.seconds) {
                    // early user feedback: migrate() returns the same event type the pathEvents flow emits, declared beside Validated and Failed
                    val (c, s) = p.connect()
                    val io2 = p.net.open(newAddr)
                    val change: PathEvent = c.migrate(io2)
                    val typed = assertIs<PathEvent.Changed>(change)
                    assertEquals(PathChangeReason.ActiveMigration, typed.reason)
                    c.close()
                    s.close()
                }
            }
        }

    @Test fun closedPathIoReleased() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(20.seconds) {
                    val (c, s) = p.connect()
                    val io2 = p.net.open(newAddr)
                    val path = c.addPath(io2)
                    assertTrue(path.probe())
                    path.close()
                    withTimeout(5.seconds) {
                        while (!io2.closed || path.state.value != PathState.Closed) delay(10)
                    } // the loop closes the socket and then marks the path: wait for both
                    assertTrue(io2.closed, "closing the path closes its socket")
                    assertEquals(PathState.Closed, path.state.value)
                    assertEquals(1, c.paths.size)
                    assertTrue(echo(c, s, 1024))
                    c.close()
                    s.close()
                }
            }
        }
}
