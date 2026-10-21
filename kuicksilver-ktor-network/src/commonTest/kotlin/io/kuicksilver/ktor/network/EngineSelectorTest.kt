// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * A socket closed on an [engineSelector] is released at once, also when that selector has nothing else to wait for
 * (Ktor issue KTOR-10016). With a plain ktor-network 3.6.0 `SelectorManager` on the JVM it was not:
 * NIO defers the close of a registered channel until the next select, and an idle `ActorSelectorManager` waits for new
 * interests instead of selecting, so the descriptor stayed open, half-closed, with the unread data in it. The peer, still
 * writing into a zero window, never learned that the connection was gone (a server handler writing an abandoned
 * response body: `AbandonedBodyTest`).
 */
@OptIn(ExperimentalAtomicApi::class)
class EngineSelectorTest {
    @Test fun socketClosedWhileTheSelectorIsIdleIsReleased() =
        runBlocking {
            val serverSelector = SelectorManager(Dispatchers.Default)
            val clientSelector = engineSelector(Dispatchers.Default)
            try {
                withTimeout(60.seconds) {
                    val listener = bindTcp(serverSelector, "127.0.0.1", 0)
                    val accepted = async { listener.accept() }
                    val client =
                        connectTcp(clientSelector, InetSocketAddress("127.0.0.1", (listener.localAddress as InetSocketAddress).port))
                    val server = accepted.await()
                    client.openReadChannel() // read by the socket into its channel, never by the application
                    val out = server.openWriteChannel()
                    val written = AtomicLong(0)
                    val writer =
                        async(Dispatchers.Default) {
                            runCatching {
                                val chunk = ByteArray(64 * 1024)
                                while (true) {
                                    out.writeFully(chunk)
                                    out.flush()
                                    written.addAndFetch(chunk.size.toLong())
                                }
                            }
                        }
                    // the writer stalls once the client's channel and both kernel buffers are full: the client's socket then waits
                    // for room in its channel, and its selector has nothing to select (the only key was just selected)
                    var last = -1L
                    while (written.load() != last) {
                        last = written.load()
                        delay(500.milliseconds)
                    }
                    assertTrue(last > 0, "nothing was written")
                    client.close()
                    val ended = withTimeoutOrNull(10.seconds) { writer.await() }
                    assertNotNull(ended, "the server still writes into a connection the client closed: its socket was not released")
                    assertTrue(ended.isFailure, "the write ended without an error")
                    server.close()
                    listener.close()
                }
            } finally {
                clientSelector.close()
                serverSelector.close()
            }
        }
}
