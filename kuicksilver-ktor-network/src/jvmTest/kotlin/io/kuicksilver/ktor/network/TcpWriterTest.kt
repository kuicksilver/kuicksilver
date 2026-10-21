// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.SessionCache
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.BeforeTest
import kotlin.test.Test
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
