// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.Selectable
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.SessionCache
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import java.net.StandardSocketOptions
import java.nio.channels.SocketChannel
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The engines' JVM TCP sockets write through Kuicksilver's own writer, not ktor-network's: ktor 3.6.0's `cio-to-nio-writer`
 * (CIOWriter.kt, attachForWritingDirectImpl) retries `SocketChannel.write` in a loop that never reaches its select while the
 * kernel's send buffer is full, so every peer that reads slower than we write kept a `Dispatchers.IO` thread at 100 % CPU,
 * uncancellable (fable review of k8/native-fixes). The peer here accepts and never reads.
 */
class TcpWriterTest {
    @BeforeTest fun load() {
        KslLoader.ensureLoaded()
        runBlocking { SessionCache.Default.clear() }
    }

    /** Threads running inside a JDK socket write right now (the spinning writer is always there; a suspended one never). */
    private fun threadsInSocketWrite(): Int =
        Thread.getAllStackTraces().count { (t, st) ->
            t.state == Thread.State.RUNNABLE &&
                st.take(8).any { it.className.startsWith("sun.nio.ch.") && it.methodName.startsWith("write") }
        }

    /** Samples until [written] has not moved for [quiet] samples in a row: the peer's window and our buffers are full. */
    private fun awaitStall(
        written: AtomicLong,
        quiet: Int = 300,
    ) {
        var last = -1L
        var still = 0
        repeat(200_000) {
            threadsInSocketWrite()
            val now = written.get()
            if (now == last) {
                if (++still >= quiet) return
            } else {
                still = 0
                last = now
            }
        }
        error("the writes never stalled ($last bytes): is the peer reading?")
    }

    /** Writes up to 64 MiB in 64 KiB chunks, counting what [out] accepted, until the peer's window and every buffer are full. */
    private fun CoroutineScope.flood(
        out: ByteWriteChannel,
        written: AtomicLong,
    ) = launch {
        val chunk = ByteArray(64 shl 10)
        repeat(1024) {
            out.writeFully(chunk, 0, chunk.size)
            written.addAndGet(chunk.size.toLong())
        }
    }

    private class NeverReadingPeer(
        val selector: SelectorManager,
        val port: Int,
        val accepted: CompletableDeferred<Socket>,
    )

    private suspend fun neverReadingPeer(
        scope: CoroutineScope,
        onAccept: suspend (Socket) -> Unit = {},
    ): NeverReadingPeer {
        val selector = SelectorManager(Dispatchers.IO)
        val server = bindTcp(selector, "127.0.0.1", 0)
        val accepted = CompletableDeferred<Socket>()
        scope.launch {
            val s = server.accept()
            accepted.complete(s)
            onAccept(s)
        }
        return NeverReadingPeer(selector, (server.localAddress as InetSocketAddress).port, accepted)
    }

    @Test fun negative_writerWaitsWithoutSpinningWhileThePeerDoesNotRead(): Unit =
        runBlocking {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val peer = neverReadingPeer(scope)
            try {
                val c = connectTcp(peer.selector, InetSocketAddress("127.0.0.1", peer.port))
                val written = AtomicLong()
                scope.flood(c.openWriteChannel(autoFlush = true), written)
                awaitStall(written)
                var hits = 0
                repeat(500) { if (threadsInSocketWrite() > 0) hits++ }
                assertTrue(hits <= 5, "a writer kept running in SocketChannel.write in $hits of 500 samples after ${written.get()} bytes")
                val waits = (c as KslNioSocket).writeWaits.get()
                assertTrue(
                    waits in 1..5,
                    "writes that answered 0 and waited for the socket: $waits (a spinning writer retries without bound)",
                )
                c.close()
            } finally {
                scope.cancel()
                peer.selector.close()
            }
        }

    /** A peer that reads and discards everything. */
    private suspend fun drainingPeer(scope: CoroutineScope): NeverReadingPeer =
        neverReadingPeer(scope) { s ->
            val input = s.openReadChannel()
            val buf = ByteArray(64 shl 10)
            while (input.readAvailable(buf, 0, buf.size) >= 0) Unit
        }

    /** The application ends its writes and waits for the writer before it closes: close() must still close the socket. */
    @Test fun closeAfterTheWriterFinishedReleasesTheSocket(): Unit =
        runBlocking {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val peer = drainingPeer(scope)
            try {
                val c = connectTcp(peer.selector, InetSocketAddress("127.0.0.1", peer.port))
                val out = ByteChannel(autoFlush = true)
                val writer = c.attachForWriting(out)
                out.writeFully(ByteArray(1 shl 20), 0, 1 shl 20)
                out.flushAndClose()
                withTimeout(20.seconds) { writer.job.join() }
                c.close()
                val released = withTimeoutOrNull(10.seconds) { c.socketContext.join() }
                assertTrue(released != null, "close() after the writer finished completes the socket")
                assertTrue(!(c as KslNioSocket).isOpen, "and closes its descriptor")
            } finally {
                scope.cancel()
                peer.selector.close()
            }
        }

    /** The peer resets the connection during a flood: the application's write fails, and close() still releases the socket. */
    @Test fun negative_closeAfterAPeerResetReleasesTheSocket(): Unit =
        runBlocking {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val reset = CompletableDeferred<Unit>()
            val peer =
                neverReadingPeer(scope) { s ->
                    reset.await()
                    val nio = ((s as KslNioSocket).ktorSocket as Selectable).channel as SocketChannel
                    nio.setOption(StandardSocketOptions.SO_LINGER, 0)
                    nio.close() // RST
                }
            try {
                val c = connectTcp(peer.selector, InetSocketAddress("127.0.0.1", peer.port))
                val out = c.openWriteChannel(autoFlush = true)
                val written = AtomicLong()
                val flood = scope.async { runCatching { scope.flood(out, written).join() } }
                awaitStall(written)
                reset.complete(Unit)
                val failure =
                    withTimeoutOrNull(20.seconds) {
                        val chunk = ByteArray(64 shl 10)
                        runCatching { while (true) out.writeFully(chunk, 0, chunk.size) }.exceptionOrNull()
                    }
                assertTrue(failure != null, "the application's writes fail after the peer's reset")
                flood.cancel()
                c.close()
                val released = withTimeoutOrNull(10.seconds) { c.socketContext.join() }
                assertTrue(released != null, "close() after a reset completes the socket")
                assertTrue(!(c as KslNioSocket).isOpen, "and closes its descriptor")
            } finally {
                scope.cancel()
                peer.selector.close()
            }
        }

    /** Plain TCP (an HTTP/1.1 response to a client that stopped reading): close() drops what is queued after its bound. */
    @Test fun negative_plainCloseIsBoundedWhileThePeerDoesNotRead(): Unit =
        runBlocking {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val peer = neverReadingPeer(scope)
            try {
                val c = connectTcp(peer.selector, InetSocketAddress("127.0.0.1", peer.port))
                (c as KslNioSocket).closeTimeout = 300.milliseconds
                val written = AtomicLong()
                scope.flood(c.openWriteChannel(autoFlush = true), written)
                awaitStall(written)
                c.close()
                val released = withTimeoutOrNull(20.seconds) { c.socketContext.join() }
                assertTrue(released != null, "close() releases the socket within its bound although the peer never reads")
                assertTrue(!c.isOpen, "and closes its descriptor")
                assertFailsWith<IOException> { c.attachForWriting(ByteChannel()) }
            } finally {
                scope.cancel()
                peer.selector.close()
            }
        }

    /**
     * A server's last response (4 MiB, 8 MiB under TLS: more than every buffer on the way holds) to a client that reads slowly
     * (about 640 KiB/s here): close() right after writing it must not
     * cut it short. The server-accepted socket has no close bound of its own (the engine owns it); a fixed 3 s one truncated
     * the response silently, the client seeing a clean EOF after part of it (k8/tcp-hardening review).
     */
    private fun slowReaderGetsEverything(
        tls: Boolean,
        size: Int,
    ): Unit =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            val server = bindTcp(selector, "127.0.0.1", 0)
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            try {
                scope.launch {
                    val accepted = server.accept()
                    val s: Socket = if (tls) accepted.tlsServer(serverConfig()) else accepted
                    val out = s.openWriteChannel(autoFlush = true)
                    out.writeFully(ByteArray(size), 0, size)
                    out.flushAndClose()
                    s.close() // the response is complete: close at once, as an engine does after `Connection: close`
                }
                val raw = connectTcp(selector, InetSocketAddress("127.0.0.1", (server.localAddress as InetSocketAddress).port))
                val c: Socket = if (tls) withTimeout(20.seconds) { raw.tls(clientConfig()) } else raw
                val input = c.openReadChannel()
                val buf = ByteArray(64 shl 10)
                var got = 0L
                var paced = 0L
                withTimeout(60.seconds) {
                    while (true) {
                        val n = input.readAvailable(buf, 0, buf.size)
                        if (n < 0) break
                        got += n
                        if (got - paced >= buf.size) { // the slow reader: 64 KiB per 100 ms, the rate is the point of the test
                            paced = got
                            delay(100)
                        }
                    }
                }
                assertEquals(size.toLong(), got, "the slow reader received the whole response before EOF")
                c.close()
            } finally {
                scope.cancel()
                server.close()
                selector.close()
            }
        }

    @Test fun negative_slowReaderGetsTheWholeResponseThroughClose() = slowReaderGetsEverything(tls = false, size = 4 shl 20)

    @Test fun negative_slowReaderGetsTheWholeTlsResponseThroughClose() =
        slowReaderGetsEverything(tls = true, size = 8 shl 20) // TLS buffers more on both sides

    @Test fun negative_tlsCloseReleasesTheSocketWhileThePeerDoesNotRead(): Unit =
        runBlocking {
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            val release = CompletableDeferred<Unit>()
            val peer = neverReadingPeer(scope) { s -> s.tlsServer(serverConfig()).also { release.await() } }
            try {
                val raw = connectTcp(peer.selector, InetSocketAddress("127.0.0.1", peer.port))
                val c = withTimeout(20.seconds) { raw.tls(clientConfig()) }
                c.closeTimeout = 300.milliseconds
                val written = AtomicLong()
                scope.flood(c.openWriteChannel(autoFlush = true), written)
                awaitStall(written)
                var hits = 0
                repeat(500) { if (threadsInSocketWrite() > 0) hits++ }
                assertTrue(hits <= 5, "under TLS too, a writer kept running in SocketChannel.write in $hits of 500 samples")
                c.close()
                val released = withTimeoutOrNull(20.seconds) { raw.socketContext.join() }
                assertTrue(released != null, "the TCP socket is released within the close bound although the peer never reads")
                assertTrue(!(raw as KslNioSocket).isOpen, "and its descriptor is closed")
                assertTrue(scope.async { threadsInSocketWrite() }.await() == 0, "no writer left in SocketChannel.write")
            } finally {
                release.complete(Unit)
                scope.cancel()
                peer.selector.close()
            }
        }
}
