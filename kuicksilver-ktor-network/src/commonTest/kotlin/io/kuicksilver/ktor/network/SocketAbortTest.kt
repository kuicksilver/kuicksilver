// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * [abort] releases a socket whose peer does not read, where a graceful `close()` waits for ever: on a plain TCP socket
 * and on a [TlsSocket] over one. Its job completes once the descriptor is released.
 */
class SocketAbortTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_abortReleasesAPlainSocketWhosePeerDoesNotRead() = abortTest(tls = false)

    @Test fun negative_abortReleasesATlsSocketWhosePeerDoesNotRead() = abortTest(tls = true)

    /**
     * The other side: a writer waiting for room on a connection its peer resets (the peer's [abort]) fails with an
     * IOException, promptly. Before, on Windows, it waited for ever: ktor-network's selector there waits for `FD_WRITE`,
     * and a reset comes as `FD_CLOSE`.
     */
    @Test fun negative_aWriterWaitingForRoomFailsWhenThePeerResets() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    val peer = server.accept() // reads nothing
                    val out = client.openWriteChannel()
                    val progress = Channel<Unit>(Channel.CONFLATED)
                    val writer =
                        async {
                            runCatching {
                                val chunk = ByteArray(64 * 1024)
                                while (true) {
                                    out.writeFully(chunk)
                                    out.flush()
                                    progress.trySend(Unit)
                                }
                            }.exceptionOrNull()
                        }
                    // until the writer is stuck (no chunk for 300 ms): the peer's buffers are full
                    while (withTimeoutOrNull(300.milliseconds) { progress.receive() } != null) continue
                    peer.abort()
                    val failure = withTimeoutOrNull(5.seconds) { writer.await() }
                    assertIs<IOException>(
                        failure,
                        "the writer on a reset connection still waits after 5 s, or did not fail with an IOException",
                    )
                    client.abort()
                    server.close()
                }
            } finally {
                selector.close()
            }
        }

    private fun abortTest(tls: Boolean) =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    coroutineScope {
                        // the peer: connects (and handshakes) and never reads
                        val peer =
                            launch {
                                val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                                if (tls) tcp.tls(clientConfig())
                            }
                        val raw = server.accept()
                        val sock: Socket = if (tls) raw.tlsServer(serverConfig()) else raw
                        val out = sock.openWriteChannel()
                        val progress = Channel<Unit>(Channel.CONFLATED)
                        launch {
                            val chunk = ByteArray(64 * 1024)
                            runCatching {
                                while (true) {
                                    out.writeFully(chunk)
                                    out.flush()
                                    progress.trySend(Unit)
                                }
                            }
                        }
                        // until the writer is stuck (no chunk for 300 ms): the peer's buffers are full
                        while (withTimeoutOrNull(300.milliseconds) { progress.receive() } != null) continue
                        sock.close()
                        // a bounded look, not a wait for something to happen: a graceful close cannot finish here
                        assertNull(withTimeoutOrNull(500.milliseconds) { raw.socketContext.join() }, "the close finished")
                        sock.abort()
                        assertNotNull(
                            withTimeoutOrNull(1.seconds) { raw.socketContext.join() },
                            "the aborted socket is still open after 1 s",
                        )
                        peer.cancel()
                        server.close()
                        coroutineContext.cancelChildren()
                    }
                }
            } finally {
                selector.close()
            }
        }
}
